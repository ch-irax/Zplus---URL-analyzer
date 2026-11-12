import { NextRequest, NextResponse } from 'next/server';
import { checkRateLimit, rateLimitResponse } from './lib/ratelimit';
import { verifyJwt } from './lib/auth';

const ALLOWED_ORIGINS = [
  'https://zplusec.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
];

const PROTECTED_ROUTES = ['/api/scan/history', '/api/user/profile'];

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;
  const origin = req.headers.get('origin');
  const method = req.method;

  // 1. CORS Headers Guard (ASVS V14.4)
  const isAllowedOrigin = origin && ALLOWED_ORIGINS.includes(origin);
  const corsHeaders: Record<string, string> = {
    'Access-Control-Allow-Origin': isAllowedOrigin ? origin : ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With, X-CSRF-Token',
    'Access-Control-Allow-Credentials': 'true',
  };

  // Handle Preflight OPTIONS Request
  if (method === 'OPTIONS') {
    return new NextResponse(null, { status: 204, headers: corsHeaders });
  }

  // 2. CSRF Guard for State-Changing API Requests (POST, PUT, DELETE)
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method) && pathname.startsWith('/api/')) {
    const fetchSite = req.headers.get('sec-fetch-site');
    // Block cross-site state-changing requests if Origin header doesn't match allowed origins
    if (fetchSite === 'cross-site' && origin && !ALLOWED_ORIGINS.includes(origin)) {
      return NextResponse.json(
        { error: 'CSRF_VIOLATION', message: 'Cross-Site Request Forgery attempt blocked' },
        { status: 403, headers: corsHeaders }
      );
    }
  }

  // 3. Global Rate Limiting Guard on API Routes (20 req/min)
  if (pathname.startsWith('/api/')) {
    const rateLimit = await checkRateLimit(req, 20);
    if (!rateLimit.success) {
      const res = rateLimitResponse(rateLimit.reset);
      Object.entries(corsHeaders).forEach(([k, v]) => res.headers.set(k, v));
      return res;
    }
  }

  // 4. JWT Authentication Guard for Protected Routes
  if (PROTECTED_ROUTES.some((route) => pathname.startsWith(route))) {
    const token = req.cookies.get('accessToken')?.value || req.headers.get('authorization')?.replace('Bearer ', '');

    if (!token || !verifyJwt(token)) {
      return NextResponse.json(
        { error: 'UNAUTHORIZED', message: 'Authentication token missing or invalid' },
        { status: 401, headers: corsHeaders }
      );
    }
  }

  // Proceed with Request & Append Security / CORS Headers
  const response = NextResponse.next();
  Object.entries(corsHeaders).forEach(([k, v]) => response.headers.set(k, v));
  return response;
}

export const config = {
  matcher: ['/api/:path*'],
};
