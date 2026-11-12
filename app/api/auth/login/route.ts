import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { checkRateLimit, rateLimitResponse } from '@/lib/ratelimit';
import { handleApiError } from '@/lib/security';
import { verifyPassword, signJwt } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

const LoginSchema = z.object({
  email: z.string().email('Invalid email address format').toLowerCase().trim(),
  password: z.string().min(1, 'Password is required'),
});

export async function POST(req: NextRequest) {
  try {
    // 1. Rate Limit Check (20 req/min - Anti Credential Stuffing)
    const rateLimit = await checkRateLimit(req, 20);
    if (!rateLimit.success) {
      return rateLimitResponse(rateLimit.reset);
    }

    // 2. Input Validation
    const body = await req.json();
    const parsed = LoginSchema.parse(body);

    // 3. User Lookup
    const user = await prisma.user.findUnique({
      where: { email: parsed.email },
    });

    // OWASP Security Note: Generic credential failure message to prevent account enumeration
    if (!user || !verifyPassword(parsed.password, user.hashedPassword)) {
      return NextResponse.json(
        { error: 'Unauthorized', message: 'Invalid email or password' },
        { status: 401 }
      );
    }

    // 4. Generate JWT Access Token
    const accessToken = signJwt({ userId: user.id, email: user.email }, 7 * 24 * 3600);

    // 5. Set Secure HTTP-Only Cookie
    const response = NextResponse.json({
      success: true,
      message: 'Authentication successful',
      user: { id: user.id, email: user.email },
    });

    response.cookies.set('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
      maxAge: 7 * 24 * 3600,
    });

    return response;
  } catch (error) {
    return handleApiError(error, 'Authentication failed');
  }
}
