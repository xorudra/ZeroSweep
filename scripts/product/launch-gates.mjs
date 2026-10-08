#!/usr/bin/env node
/**
 * v1.0 launch gate evaluation (Prompt 40 §267–§272).
 *
 * Reads RECORDED EVIDENCE (test results, RC findings, deployment
 * configuration) and evaluates every launch gate. Nothing here invents
 * a pass: a gate without evidence is BLOCKED, and conditional gates
 * (billing, licensing) are NOT_APPLICABLE only when the capability is
 * genuinely disabled in the evaluated deployment configuration
 * (§268/§269). The final status is exactly V1_READY or V1_BLOCKED.
 *
 * Usage:
 *   node scripts/product/launch-gates.mjs --evidence <evidence.json> [--out <dir>]
 *
 * Evidence JSON shape (all fields optional; missing = not evidenced):
 * {
 *   "rcStatus": "RC_READY" | "RC_BLOCKED",
 *   "rcBlockersOpen": 0, "rcCriticalsOpen": 0,
 *   "tests": { "suitesPassed": true, "tsTestsPassed": 2170, "pytestPassed": 6 },
 *   "liveRegression": { "allPassed": true, "checks": 300 },
 *   "tenantIsolationTestsPassed": true,
 *   "authorizationTestsPassed": true,
 *   "entitlementTestsPassed": true,
 *   "quotaTestsPassed": true,
 *   "meteringTestsPassed": true,
 *   "onboardingVerifiedLive": true,
 *   "backupVerified": true, "restoreVerified": true,
 *   "productionDeploymentVerified": true,
 *   "documentationComplete": true,
 *   "billing": { "enabled": false },
 *   "billingSecurityTestsPassed": false,
 *   "licensing": { "enabled": false },
 *   "licenseSecurityTestsPassed": false
 * }
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const GATES = [
  { key: "RC_SECURITY", name: "RC security audit clean (no open BLOCKER/CRITICAL)" },
  { key: "TENANT_ISOLATION", name: "Tenant isolation verified" },
  { key: "AUTHORIZATION", name: "Authorization model verified" },
  { key: "PRODUCT_ENTITLEMENT", name: "Product entitlement enforcement verified" },
  { key: "QUOTA", name: "Quota enforcement verified" },
  { key: "METERING", name: "Usage metering verified" },
  { key: "BILLING_SECURITY", name: "Billing security verified" },
  { key: "LICENSE_SECURITY", name: "License security verified" },
  { key: "ONBOARDING", name: "Customer onboarding verified" },
  { key: "BACKUP", name: "Backup verified" },
  { key: "RESTORE", name: "Restore verified" },
  { key: "PRODUCTION_DEPLOYMENT", name: "Production deployment verified" },
  { key: "DOCUMENTATION", name: "Documentation complete" },
  { key: "NO_BLOCKER_DEFECTS", name: "No blocker defects open" },
];

function evaluate(ev) {
  const results = [];
  const push = (key, status, evidence) => results.push({ gate: key, status, evidence });
  const rcClean = ev.rcStatus === "RC_READY" && (ev.rcBlockersOpen ?? 1) === 0 && (ev.rcCriticalsOpen ?? 1) === 0;
  push("RC_SECURITY", rcClean ? "PASS" : "BLOCKED", `rcStatus=${ev.rcStatus ?? "unknown"}, blockers=${ev.rcBlockersOpen ?? "unknown"}, criticals=${ev.rcCriticalsOpen ?? "unknown"}`);
  push("TENANT_ISOLATION", ev.tenantIsolationTestsPassed ? "PASS" : "BLOCKED", "tenant isolation test battery");
  push("AUTHORIZATION", ev.authorizationTestsPassed ? "PASS" : "BLOCKED", "authorization/scope test battery");
  push("PRODUCT_ENTITLEMENT", ev.entitlementTestsPassed ? "PASS" : "BLOCKED", "entitlement fail-closed tests");
  push("QUOTA", ev.quotaTestsPassed ? "PASS" : "BLOCKED", "quota check/reserve/race tests");
  push("METERING", ev.meteringTestsPassed ? "PASS" : "BLOCKED", "metering idempotency tests");
  if (ev.billing?.enabled) push("BILLING_SECURITY", ev.billingSecurityTestsPassed ? "PASS" : "BLOCKED", "billing enabled in deployment; webhook/idempotency tests required");
  else push("BILLING_SECURITY", "NOT_APPLICABLE", "billing provider not configured in the evaluated deployment (§268)");
  if (ev.licensing?.enabled) push("LICENSE_SECURITY", ev.licenseSecurityTestsPassed ? "PASS" : "BLOCKED", "licensing enabled in deployment; signature/tamper/expiry tests required");
  else push("LICENSE_SECURITY", "NOT_APPLICABLE", "license verification not enabled in the evaluated deployment (§269)");
  push("ONBOARDING", ev.onboardingVerifiedLive ? "PASS" : "BLOCKED", "live onboarding smoke");
  push("BACKUP", ev.backupVerified ? "PASS" : "BLOCKED", "platform backup evidence");
  push("RESTORE", ev.restoreVerified ? "PASS" : "BLOCKED", "isolated restore evidence");
  push("PRODUCTION_DEPLOYMENT", ev.productionDeploymentVerified ? "PASS" : "BLOCKED", "live stack regression battery");
  push("DOCUMENTATION", ev.documentationComplete ? "PASS" : "BLOCKED", "documentation audit (§293)");
  push("NO_BLOCKER_DEFECTS", (ev.rcBlockersOpen ?? 1) === 0 ? "PASS" : "BLOCKED", "RC findings register");
  const blocked = results.filter((r) => r.status === "BLOCKED");
  return { results, status: blocked.length === 0 ? "V1_READY" : "V1_BLOCKED", blocked: blocked.map((b) => b.gate) };
}

const args = process.argv.slice(2);
const evidencePath = args[args.indexOf("--evidence") + 1];
if (!evidencePath) { console.error("Usage: launch-gates.mjs --evidence <evidence.json> [--out <dir>]"); process.exit(2); }
const evidence = JSON.parse(readFileSync(evidencePath, "utf8"));
const { results, status, blocked } = evaluate(evidence);

console.log(`DSRclone v1.0 launch gates — evaluated ${new Date().toISOString()}`);
for (const g of GATES) {
  const r = results.find((x) => x.gate === g.key);
  console.log(`  [${r.status.padEnd(14)}] ${g.key} — ${g.name} (${r.evidence})`);
}
console.log(`FINAL STATUS: ${status}${blocked.length ? ` — blocked by: ${blocked.join(", ")}` : ""}`);

const outIdx = args.indexOf("--out");
if (outIdx >= 0) {
  const dir = resolve(args[outIdx + 1]);
  mkdirSync(dir, { recursive: true });
  writeFileSync(resolve(dir, "gate-results.json"), JSON.stringify({ evaluatedAt: new Date().toISOString(), status, results }, null, 2));
  console.log(`Wrote ${resolve(dir, "gate-results.json")}`);
}
process.exit(status === "V1_READY" ? 0 : 1);
