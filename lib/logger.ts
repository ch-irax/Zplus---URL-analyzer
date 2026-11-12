import { prisma } from './prisma';

export interface AuditLogParams {
  userId?: string | null;
  action: string;
  ip: string;
  userAgent?: string | null;
  details?: Record<string, unknown> | string;
}

/**
 * ASVS V7 Audit Logger
 * Records security-critical events (Logins, Failed Scans, SSRF blocks, Rate Limit violations) to Postgres DB
 */
export async function logAuditEvent(params: AuditLogParams): Promise<void> {
  const { userId, action, ip, userAgent, details } = params;
  const serializedDetails = typeof details === 'object' ? JSON.stringify(details) : details || null;

  // Console structured log output
  const timestamp = new Date().toISOString();
  console.log(`[AUDIT_LOG] [${timestamp}] ACTION=${action} IP=${ip} USER=${userId || 'ANONYMOUS'}`);

  try {
    // Persist Audit Log in Postgres Database via Prisma
    await prisma.auditLog.create({
      data: {
        userId: userId || null,
        action,
        ip,
        userAgent: userAgent || null,
        details: serializedDetails,
      },
    });
  } catch (err) {
    console.error('[AUDIT_LOG_ERROR] Failed to persist audit record to database:', err);
  }
}
