import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { checkRateLimit, rateLimitResponse } from '@/lib/ratelimit';
import { handleApiError } from '@/lib/security';
import { hashPassword, signJwt } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

// ASVS Level 2 Password & Email Validation Schema
const RegisterSchema = z.object({
  email: z.string().email('Invalid email address format').toLowerCase().trim(),
  password: z
    .string()
    .min(8, 'Password must be at least 8 characters long')
    .max(128, 'Password must not exceed 128 characters'),
});

export async function POST(req: NextRequest) {
  try {
    // 1. Rate Limit Check (20 req/min)
    const rateLimit = await checkRateLimit(req, 20);
    if (!rateLimit.success) {
      return rateLimitResponse(rateLimit.reset);
    }

    // 2. Input Validation
    const body = await req.json();
    const parsed = RegisterSchema.parse(body);

    // 3. Check for existing user
    const existingUser = await prisma.user.findUnique({
      where: { email: parsed.email },
    });

    if (existingUser) {
      return NextResponse.json(
        { error: 'Registration Failed', message: 'User with this email already exists' },
        { status: 409 }
      );
    }

    // 4. Hash Password & Create User
    const hashedPassword = hashPassword(parsed.password);
    const newUser = await prisma.user.create({
      data: {
        email: parsed.email,
        hashedPassword,
      },
    });

    // 5. Generate JWT Access Token
    const accessToken = signJwt({ userId: newUser.id, email: newUser.email }, 7 * 24 * 3600);

    // 6. Set Secure HTTP-Only Cookie
    const response = NextResponse.json({
      success: true,
      message: 'Account created successfully',
      user: { id: newUser.id, email: newUser.email, createdAt: newUser.createdAt },
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
    return handleApiError(error, 'User registration failed');
  }
}
