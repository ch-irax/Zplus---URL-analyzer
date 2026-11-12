import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, rateLimitResponse } from '@/lib/ratelimit';
import { handleApiError } from '@/lib/security';
import { getAuthUser } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

export async function GET(req: NextRequest) {
  try {
    // 1. Rate Limit Check (20 req/min)
    const rateLimit = await checkRateLimit(req, 20);
    if (!rateLimit.success) {
      return rateLimitResponse(rateLimit.reset);
    }

    // 2. Auth Guard: Require valid JWT session
    const authUser = getAuthUser(req);
    if (!authUser) {
      return NextResponse.json(
        { error: 'Unauthorized', message: 'Authentication required to view scan history' },
        { status: 401 }
      );
    }

    // 3. Parse Pagination Query Params
    const url = new URL(req.url);
    const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10));
    const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit') || '10', 10)));
    const skip = (page - 1) * limit;

    // 4. Query Scan History from Prisma DB
    const [scans, totalCount] = await Promise.all([
      prisma.scan.findMany({
        where: { userId: authUser.userId },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        include: {
          redirectionTraces: {
            orderBy: { hopNumber: 'asc' },
          },
          nodeIntelligences: true,
        },
      }),
      prisma.scan.count({
        where: { userId: authUser.userId },
      }),
    ]);

    // 5. Return Structured Response
    return NextResponse.json({
      success: true,
      scans: scans.map((scan) => ({
        id: scan.id,
        originalUrl: scan.originalUrl,
        normalizedUrl: scan.normalizedUrl,
        trustScore: scan.trustScore,
        maliciousFlag: scan.maliciousFlag,
        sandboxHash: scan.sandboxHash,
        redirectionCount: scan.redirectionTraces.length,
        redirectionTraces: scan.redirectionTraces,
        nodeIntelligences: scan.nodeIntelligences,
        createdAt: scan.createdAt,
      })),
      pagination: {
        page,
        limit,
        total: totalCount,
        totalPages: Math.ceil(totalCount / limit),
      },
    });
  } catch (error) {
    return handleApiError(error, 'Failed to fetch scan history');
  }
}
