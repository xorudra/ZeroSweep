/** Password policy (§21): length bounds + optional history + compromised-
 *  list hook. No arbitrary composition rules unless an org requires them —
 *  length is the control that matters. */
export interface PasswordPolicyShape {
  minLength: number;
  maxLength: number;
  historyCount: number;
  compromisedCheckEnabled: boolean;
}

export const DEFAULT_PASSWORD_POLICY: PasswordPolicyShape = {
  minLength: 12,
  maxLength: 128,
  historyCount: 5,
  compromisedCheckEnabled: false,
};

export function evaluatePassword(password: string, policy: PasswordPolicyShape, opts: { isCompromised?: (pw: string) => boolean } = {}): { ok: boolean; failures: string[] } {
  const failures: string[] = [];
  if (password.length < policy.minLength) failures.push(`Password must be at least ${policy.minLength} characters`);
  if (password.length > policy.maxLength) failures.push(`Password must be at most ${policy.maxLength} characters`);
  if (policy.compromisedCheckEnabled && opts.isCompromised?.(password)) failures.push("Password appears in compromised-password data");
  return { ok: failures.length === 0, failures };
}

/** Login/recovery rate limiting (§22): bounded by account+IP buckets. The
 *  decision is pure so it can be unit-tested deterministically. */
export interface AttemptBucket { key: string; count: number; windowStartMs: number }
export function rateLimitDecision(buckets: AttemptBucket[], key: string, nowMs: number, limit = 10, windowMs = 15 * 60 * 1000): { allowed: boolean; retryAfterMs: number } {
  const bucket = buckets.find((b) => b.key === key && nowMs - b.windowStartMs < windowMs);
  if (!bucket) return { allowed: true, retryAfterMs: 0 };
  if (bucket.count >= limit) return { allowed: false, retryAfterMs: windowMs - (nowMs - bucket.windowStartMs) };
  return { allowed: true, retryAfterMs: 0 };
}

/** Generic failure surface (§23): login, reset and MFA errors never reveal
 *  whether the account exists or which factor failed. */
export const GENERIC_AUTH_ERROR = "Invalid email or password";
export const GENERIC_RESET_MESSAGE = "If an account exists for that address, a reset message has been sent";
