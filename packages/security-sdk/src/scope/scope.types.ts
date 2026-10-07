import type { ScopeRules } from "@dsrclone/validation";

export type { ScopeRules };

/** Result of asking the ScopeMatcher about one discovered asset/endpoint. */
export interface ScopeCheckResult {
  allowed: boolean;
  reason?: string;
}
