/** Email normalization (§18): trim + lowercase the whole address for identity
 *  matching. Provider-specific alias rules (dots, plus tags) are NOT assumed
 *  unless an organization explicitly configures them — it does not. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function emailDomain(email: string): string | null {
  const normalized = normalizeEmail(email);
  const at = normalized.lastIndexOf("@");
  if (at <= 0 || at === normalized.length - 1) return null;
  return normalized.slice(at + 1);
}
