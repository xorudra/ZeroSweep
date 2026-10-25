import type { TargetType } from "@zerosweep/types";

/** A target as handed to an adapter, after API-side validation. */
export interface AdapterTargetInput {
  type: TargetType;
  value: string;
  host: string;
}

export interface TargetValidationResult {
  valid: boolean;
  /** Machine-readable reason when invalid: SHELL_METACHARACTERS, INVALID_PROTOCOL,
   *  INVALID_DOMAIN, INVALID_IP, INVALID_CIDR, BLOCKED_TARGET, EMPTY. */
  reasonCode?: string;
  message?: string;
  normalizedHost?: string;
}
