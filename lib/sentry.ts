/**
 * Sentry Real-Time Error Tracking & Telemetry Guard
 */
export function captureException(error: unknown, context?: Record<string, unknown>): void {
  const timestamp = new Date().toISOString();
  console.error(`[SENTRY_TELEMETRY] [${timestamp}]`, error, context || '');

  // Sentry SDK integration wrapper
  if (process.env.SENTRY_DSN) {
    try {
      // In production with SENTRY_DSN set, dispatch payload
      fetch(process.env.SENTRY_DSN, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          exception: String(error),
          extra: context,
          environment: process.env.NODE_ENV,
        }),
      }).catch(() => {});
    } catch {
      // Silent error logging fallback
    }
  }
}
