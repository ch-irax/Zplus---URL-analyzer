import { NextResponse } from 'next/server';
import { ZodError } from 'zod';

/**
 * Validates whether a URL attempts Server-Side Request Forgery (SSRF)
 * Blocks private IP ranges, localhost, and AWS/Cloud metadata endpoints
 */
export function isForbiddenHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();

  // Block localhost & local domain variations
  if (lower === 'localhost' || lower.endsWith('.local') || lower.endsWith('.internal')) {
    return true;
  }

  // IPv4 & IPv6 regex patterns for private / link-local addresses
  const privateIpPatterns = [
    /^127\.\d+\.\d+\.\d+$/,                  // Loopback 127.0.0.0/8
    /^10\.\d+\.\d+\.\d+$/,                   // Private 10.0.0.0/8
    /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,   // Private 172.16.0.0/12
    /^192\.168\.\d+\.\d+$/,                  // Private 192.168.0.0/16
    /^169\.254\.\d+\.\d+$/,                  // Link-Local / AWS Metadata 169.254.0.0/16
    /^0\.0\.0\.0$/,                          // Any interface
    /^::1$/,                                 // IPv6 Loopback
    /^fc00:/i,                               // IPv6 Unique Local
    /^fe80:/i,                               // IPv6 Link Local
  ];

  return privateIpPatterns.some((pattern) => pattern.test(hostname));
}

/**
 * Sanitizes input string to prevent XSS / HTML Injection
 */
export function sanitizeString(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}

/**
 * Standardized OWASP-Compliant Error Response
 * Prevents stack trace leakages and raw database error exposure
 */
export function handleApiError(error: unknown, defaultMessage = 'An internal security error occurred') {
  console.error('[API_ERROR]', error);

  if (error instanceof ZodError) {
    return NextResponse.json(
      {
        error: 'Validation Failed',
        message: 'Invalid input payload structure',
        details: error.issues.map((issue) => ({
          field: issue.path.join('.'),
          message: issue.message,
        })),
      },
      { status: 400 }
    );
  }

  if (error instanceof Error) {
    if (error.message.includes('SSRF_DETECTED')) {
      return NextResponse.json(
        { error: 'Security Violation', message: 'Target IP or hostname is restricted for scanning.' },
        { status: 400 }
      );
    }
  }

  return NextResponse.json(
    {
      error: 'Internal Error',
      message: defaultMessage,
    },
    { status: 500 }
  );
}
