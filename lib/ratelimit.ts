import { NextRequest, NextResponse } from 'next/server';

export interface RateLimitResult {
  success: boolean;
  limit: number;
  remaining: number;
  reset: number;
}

// In-memory token bucket sliding window fallback for local / basic Vercel instances
const memoryStore = new Map<string, { count: number; resetTime: number }>();

/**
 * Serverless-compatible Rate Limiter (20 requests per minute by default)
 * Uses IP address + optional route prefix as key
 */
export async function checkRateLimit(
  req: NextRequest,
  limit: number = 20,
  windowMs: number = 60 * 1000
): Promise<RateLimitResult> {
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || '127.0.0.1';
  const route = req.nextUrl.pathname;
  const key = `ratelimit:${route}:${ip}`;

  const now = Date.now();
  const record = memoryStore.get(key);

  // Clean up stale memory store entries periodically
  if (memoryStore.size > 10000) {
    for (const [k, v] of memoryStore.entries()) {
      if (now > v.resetTime) memoryStore.delete(k);
    }
  }

  if (!record || now > record.resetTime) {
    memoryStore.set(key, { count: 1, resetTime: now + windowMs });
    return { success: true, limit, remaining: limit - 1, reset: now + windowMs };
  }

  if (record.count >= limit) {
    return { success: false, limit, remaining: 0, reset: record.resetTime };
  }

  record.count += 1;
  return { success: true, limit, remaining: limit - record.count, reset: record.resetTime };
}

export function rateLimitResponse(reset: number): NextResponse {
  const retryAfter = Math.ceil((reset - Date.now()) / 1000);
  return NextResponse.json(
    {
      error: 'Too Many Requests',
      message: 'Rate limit exceeded (20 req/min). Please wait before scanning again.',
      code: 'RATE_LIMIT_EXCEEDED',
    },
    {
      status: 429,
      headers: {
        'Retry-After': String(retryAfter > 0 ? retryAfter : 60),
        'X-RateLimit-Limit': '20',
        'X-RateLimit-Remaining': '0',
      },
    }
  );
}
