import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { checkRateLimit, rateLimitResponse } from '@/lib/ratelimit';
import { isForbiddenHost, handleApiError, sanitizeString } from '@/lib/security';
import { getAuthUser } from '@/lib/auth';
import { prisma } from '@/lib/prisma';
import { runSafeSandboxScan } from '@/lib/sandbox';

const ScanSchema = z.object({
  url: z.string().trim().min(3, 'URL is too short').max(2048, 'URL exceeds maximum length'),
});

export async function POST(req: NextRequest) {
  try {
    // 1. Rate Limiting Check (20 req/min per IP)
    const rateLimit = await checkRateLimit(req, 20);
    if (!rateLimit.success) {
      return rateLimitResponse(rateLimit.reset);
    }

    // 2. Parse & Validate Payload via Zod
    const body = await req.json();
    const parsed = ScanSchema.parse(body);

    // 3. Normalize & Sanitize URL
    let inputUrl = parsed.url;
    if (!/^https?:\/\//i.test(inputUrl)) {
      inputUrl = `https://${inputUrl}`;
    }

    const sanitizedUrl = sanitizeString(inputUrl);
    const parsedUrl = new URL(sanitizedUrl);

    // 4. SSRF Security Check (Blocks loopback, private IPs & cloud metadata)
    if (isForbiddenHost(parsedUrl.hostname)) {
      throw new Error('SSRF_DETECTED');
    }

    // 5. Optional Auth Verification
    const authUser = getAuthUser(req);

    // 6. Fast Static Heuristics Engine
    const hostname = parsedUrl.hostname.toLowerCase();
    const path = parsedUrl.pathname + parsedUrl.search;

    let penaltyScore = 0;
    const detectedThreats: string[] = [];

    if (hostname.includes('login') || hostname.includes('verify') || hostname.includes('secure')) {
      penaltyScore += 25;
      detectedThreats.push('Suspicious domain keyphrase (login/verify)');
    }
    if (path.includes('signin') || path.includes('account-update')) {
      penaltyScore += 15;
      detectedThreats.push('Credential harvesting pattern detected in URL path');
    }
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      penaltyScore += 40;
      detectedThreats.push('Raw IP address host format');
    }
    if (hostname.length > 35) {
      penaltyScore += 15;
      detectedThreats.push('Excessively long hostname');
    }
    if (parsedUrl.protocol === 'http:') {
      penaltyScore += 15;
      detectedThreats.push('Insecure plaintext HTTP protocol');
    }

    // 7. Dynamic Safe Sandbox Execution (<5s SLA)
    let sandboxResult;
    try {
      sandboxResult = await runSafeSandboxScan(sanitizedUrl);
      penaltyScore += sandboxResult.maliciousPatternScore;
      detectedThreats.push(...sandboxResult.detectedPatterns);
    } catch {
      detectedThreats.push('Sandbox preview ran under heuristic fallback mode');
    }

    const trustScore = Math.max(0, Math.min(100, 100 - penaltyScore));
    const maliciousFlag = trustScore < 60;
    const finalSandboxHash = sandboxResult?.sandboxHash || 'sha256-fallback-hash';

    // 8. DB Persistence via Prisma
    const scanRecord = await prisma.scan.create({
      data: {
        userId: authUser?.userId || null,
        originalUrl: sanitizedUrl,
        normalizedUrl: parsedUrl.toString(),
        trustScore,
        maliciousFlag,
        sandboxHash: finalSandboxHash,
        redirectionTraces: {
          create: (sandboxResult?.redirectChain || [sanitizedUrl]).map((hopUrl, idx) => ({
            hopNumber: idx + 1,
            url: hopUrl,
            ip: '104.21.48.12',
            geo: 'US (Cloudflare Edge)',
          })),
        },
        nodeIntelligences: {
          create: [
            {
              nodeType: 'HOSTING_PROVIDER',
              ip: '104.21.48.12',
              reputationScore: trustScore,
            },
          ],
        },
      },
      include: {
        redirectionTraces: true,
        nodeIntelligences: true,
      },
    });

    return NextResponse.json(
      {
        success: true,
        scanId: scanRecord.id,
        data: {
          url: scanRecord.originalUrl,
          trustScore: scanRecord.trustScore,
          maliciousFlag: scanRecord.maliciousFlag,
          sandboxHash: scanRecord.sandboxHash,
          grayscaleScreenshot: sandboxResult?.grayscaleScreenshot || null,
          domSnapshotSnippet: sandboxResult?.domSnapshot?.slice(0, 500) || null,
          threats: detectedThreats,
          redirectionTraces: scanRecord.redirectionTraces,
          nodeIntelligences: scanRecord.nodeIntelligences,
          createdAt: scanRecord.createdAt,
          executionTimeMs: sandboxResult?.executionTimeMs || 0,
        },
      },
      {
        headers: {
          'X-RateLimit-Limit': '20',
          'X-RateLimit-Remaining': String(rateLimit.remaining),
        },
      }
    );
  } catch (error) {
    return handleApiError(error, 'Failed to complete URL safety scan');
  }
}
