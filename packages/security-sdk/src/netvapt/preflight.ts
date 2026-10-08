import { evaluateNetworkAuthorization, type NetworkAuthorizationFacts } from "./targets";
import type { NetworkPreflightStatus } from "./types";

/**
 * Network preflight (Prompt 33 §8/§9).
 *
 * Facts split into two kinds, kept visibly separate in the checks:
 * AUTHORIZATION facts come from real platform records (verified parent
 * target, the APPROVED assessment, scope coverage) and are decisive.
 * REACHABILITY / worker facts traverse a transport seam: no live
 * network probe transport is wired in this deployment, so routing and
 * worker capability report NOT_CONFIGURED and the verdict is honestly
 * TOOL_UNAVAILABLE — reachability is never assumed (§8), exactly the
 * Prompt 32 §7/§8 discipline applied to networks.
 */

export interface NetworkPreflightCheck {
  name: string;
  status: "PASS" | "WARN" | "FAIL" | "NOT_CONFIGURED";
  detail: string;
}

export interface NetworkPreflightInput {
  targetSyntaxOk: boolean;
  targetSyntaxDetail?: string;
  scopeHostCount: number;
  budgetMaxHosts: number;
  authorization: NetworkAuthorizationFacts;
  /** Transport seam for routing/worker/tool facts. */
  transport: "NOT_CONFIGURED" | "CONFIGURED";
  toolHealth?: Array<{ slug: string; status: string }>;
  requiredTools: string[];
  masscanRequested?: boolean;
  masscanApproved?: boolean;
  rateWithinPolicy: boolean;
  maintenanceBlocked?: boolean;
}

export interface NetworkPreflightResult {
  status: NetworkPreflightStatus;
  checks: NetworkPreflightCheck[];
}

export function evaluateNetworkPreflight(input: NetworkPreflightInput): NetworkPreflightResult {
  const checks: NetworkPreflightCheck[] = [];

  checks.push({
    name: "target-syntax",
    status: input.targetSyntaxOk ? "PASS" : "FAIL",
    detail: input.targetSyntaxOk ? "Target normalized (IPv4/IPv6/CIDR/hostname) before scope creation (§6)" : (input.targetSyntaxDetail ?? "Target failed normalization (§6)"),
  });

  const scopeOk = input.scopeHostCount <= input.budgetMaxHosts;
  checks.push({
    name: "scope-size",
    status: scopeOk ? "PASS" : "FAIL",
    detail: scopeOk
      ? `Scope spans ${input.scopeHostCount} hosts within the budget ceiling of ${input.budgetMaxHosts} (§5/§17)`
      : `Scope spans ${input.scopeHostCount} hosts — above the budget ceiling of ${input.budgetMaxHosts} (§5/§140)`,
  });

  const auth = evaluateNetworkAuthorization(input.authorization);
  checks.push({
    name: "authorization",
    status: auth.allowed ? "PASS" : "FAIL",
    detail: auth.allowed ? "Authorization exists, is active, covers the target, and allows the tool + profile (§7)" : auth.failures.join("; "),
  });

  checks.push({
    name: "rate-policy",
    status: input.rateWithinPolicy ? "PASS" : "FAIL",
    detail: input.rateWithinPolicy ? "Requested rate is within platform policy (§8)" : "Requested rate exceeds platform policy — refused, not silently honored (§139)",
  });

  if (input.maintenanceBlocked) {
    checks.push({ name: "maintenance-window", status: "FAIL", detail: "A maintenance restriction covers this target window (§8)" });
  }

  if (input.masscanRequested) {
    checks.push({
      name: "masscan-gate",
      status: input.masscanApproved ? "PASS" : "FAIL",
      detail: input.masscanApproved ? "Masscan gate approved (§27)" : "MASSCAN_NOT_APPROVED — high-throughput discovery lacks its explicit profile/permission/platform record (§27)",
    });
  }

  // Transport-seam facts: routing availability, worker capability, tool
  // health. In this deployment the seam is NOT_CONFIGURED, so these are
  // reported as such and dominate the verdict (§8/§9).
  const transportConfigured = input.transport === "CONFIGURED";
  checks.push({
    name: "routing-availability",
    status: transportConfigured ? "PASS" : "NOT_CONFIGURED",
    detail: transportConfigured ? "Scanner worker routing to the target network confirmed" : "No live network probe transport is wired in this deployment (NOT_CONFIGURED) — reachability is not assumed (§8)",
  });
  const missingTools = transportConfigured
    ? input.requiredTools.filter((slug) => !(input.toolHealth ?? []).some((t) => t.slug === slug && (t.status === "HEALTHY" || t.status === "AVAILABLE")))
    : input.requiredTools;
  checks.push({
    name: "tool-health",
    status: !transportConfigured ? "NOT_CONFIGURED" : missingTools.length === 0 ? "PASS" : "FAIL",
    detail: !transportConfigured
      ? "Tool health cannot be confirmed without a wired worker transport (NOT_CONFIGURED)"
      : missingTools.length === 0 ? "All required tools report healthy on an authorized worker" : `Required tools unavailable: ${missingTools.join(", ")}`,
  });
  checks.push({
    name: "worker-capability",
    status: transportConfigured ? "PASS" : "NOT_CONFIGURED",
    detail: transportConfigured ? "An authorized scanner worker advertises the required capabilities" : "Scanner-worker capability is NOT_CONFIGURED in this deployment — L2/capture capabilities are never assumed (§20)",
  });

  const anyFail = checks.some((c) => c.status === "FAIL");
  if (anyFail) return { status: "BLOCKED", checks };
  if (!transportConfigured) return { status: "TOOL_UNAVAILABLE", checks };
  const anyWarn = checks.some((c) => c.status === "WARN");
  return { status: anyWarn ? "READY_WITH_WARNINGS" : "READY", checks };
}
