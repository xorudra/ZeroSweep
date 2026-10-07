/**
 * Validation kill switches (Prompt 16 §43, §89). Levels: GLOBAL,
 * ORGANIZATION, WORKSPACE, SCAN, TARGET, SESSION. Any matching ACTIVE
 * switch blocks new validations and terminates running ones — the
 * worker polls between validator steps, and emergency cancellation
 * terminates the active validation process rather than letting it
 * finish its current step gracefully.
 */

export const KILL_SWITCH_LEVELS = ["GLOBAL", "ORGANIZATION", "WORKSPACE", "SCAN", "TARGET", "SESSION"] as const;
export type KillSwitchLevel = (typeof KILL_SWITCH_LEVELS)[number];

export interface KillSwitchRecord {
  level: string;
  organizationId?: string | null;
  workspaceId?: string | null;
  scopeRef?: string | null;
  active: boolean;
}

export interface KillSwitchContext {
  organizationId?: string;
  workspaceId: string;
  scanId?: string;
  targetId: string;
  sessionId?: string;
}

/** Returns the most specific matching active switch, or null. */
export function activeKillSwitch(switches: KillSwitchRecord[], ctx: KillSwitchContext): KillSwitchRecord | null {
  const active = switches.filter((s) => s.active);
  const matches = (s: KillSwitchRecord): boolean => {
    switch (s.level) {
      case "GLOBAL":
        return true;
      case "ORGANIZATION":
        return Boolean(ctx.organizationId) && s.organizationId === ctx.organizationId;
      case "WORKSPACE":
        return s.workspaceId === ctx.workspaceId;
      case "SCAN":
        return Boolean(ctx.scanId) && s.scopeRef === ctx.scanId;
      case "TARGET":
        return s.scopeRef === ctx.targetId;
      case "SESSION":
        return Boolean(ctx.sessionId) && s.scopeRef === ctx.sessionId;
      default:
        return false;
    }
  };
  const specificity: Record<string, number> = { SESSION: 5, TARGET: 4, SCAN: 3, WORKSPACE: 2, ORGANIZATION: 1, GLOBAL: 0 };
  return active.filter(matches).sort((a, b) => (specificity[b.level] ?? 0) - (specificity[a.level] ?? 0))[0] ?? null;
}

export function isKillSwitchActive(switches: KillSwitchRecord[], ctx: KillSwitchContext): boolean {
  return activeKillSwitch(switches, ctx) !== null;
}
