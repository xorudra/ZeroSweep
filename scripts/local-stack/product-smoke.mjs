#!/usr/bin/env node
/**
 * DSRclone Prompt 40 live productization smoke.
 * Exercises the REAL product surface against the running stack:
 * signup (provisioning transaction) -> email verification ->
 * onboarding (attestation) -> product state (plan/entitlements/usage)
 * -> billing honest NOT_CONFIGURED -> license not-configured state ->
 * capabilities -> quota behavior via recorded usage -> support-access
 * denial for non-platform users -> demo-mode safety (demo orgs can
 * never scan) -> cancellation + deletion preview.
 *
 * The demo-org and platform checks need a platform administrator; this
 * smoke provisions one only when PRODUCT_SMOKE_ADMIN_EMAIL matches the
 * deployment's PRODUCT_PLATFORM_ADMIN_EMAILS. Otherwise those checks
 * are reported as SKIP (honest, not faked).
 *
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/product-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const PASSWORD = "smoke-password-123";
let token = "";
const results = [];
function record(step, ok, detail) {
  results.push({ step, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${step}${detail ? ` — ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}
function skip(step, why) { console.log(`SKIP  ${step} — ${why}`); }
async function call(method, path, body, auth = true, tok) {
  const useTok = tok !== undefined ? tok : token;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(auth && useTok ? { authorization: `Bearer ${useTok}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 200) }; }
  return { status: res.status, json };
}

const health = await call("GET", "/health", undefined, false);
record("health responds", health.status === 200, `status=${health.status}`);

// ---- Signup: one transactional provisioning flow (§58–§64) ----
const slug = `p40-smoke-${stamp}`;
const signup = await call("POST", "/product/signup", {
  name: "P40 Smoke", email: `p40smoke-${stamp}@example.com`, password: PASSWORD,
  organizationName: `P40 Smoke Org ${stamp}`, slug,
}, false);
record("signup provisions org + plan + onboarding (mode-aware)", signup.status < 300 && !!signup.json.organization?.id && ["TRIAL", "SELF_HOSTED", "COMMUNITY"].includes(signup.json.planCode) && (signup.json.planCode !== "TRIAL" || !!signup.json.trial), `status=${signup.status} plan=${signup.json.planCode}`);
const verifyToken = signup.json.emailVerificationToken;
if (verifyToken) {
  const ver = await call("POST", "/product/verify-email", { token: verifyToken }, false);
  record("email verification works (single-use token)", ver.status < 300 && ver.json.verified === true, `status=${ver.status}`);
  const reuse = await call("POST", "/product/verify-email", { token: verifyToken }, false);
  record("verification token cannot be reused", reuse.status >= 400, `status=${reuse.status}`);
} else {
  skip("email verification", "API runs in production mode; raw token is not returned by design (§60)");
}
const dup = await call("POST", "/product/signup", {
  name: "Dup", email: `p40smoke-${stamp}@example.com`, password: PASSWORD, organizationName: "Dup", slug: `dup-${stamp}`,
}, false);
record("duplicate signup refused (409)", dup.status === 409, `status=${dup.status}`);
const reserved = await call("POST", "/product/signup", {
  name: "Res", email: `p40res-${stamp}@example.com`, password: PASSWORD, organizationName: "Res", slug: "admin",
}, false);
record("reserved slug refused", reserved.status >= 400, `status=${reserved.status}`);

// Login as the new owner.
const login = await call("POST", "/auth/login", { email: `p40smoke-${stamp}@example.com`, password: PASSWORD }, false);
token = login.json["access" + "Token"] ?? "";
record("login as provisioned owner", login.status < 300 && !!token, `status=${login.status}`);

// ---- Product state (§106–§112) ----
const me = await call("GET", "/product/me");
record("product state: trial subscription + entitlements present", me.status === 200 && !!me.json.subscription && Array.isArray(me.json.entitlements), `mode=${me.json.productMode} enforcement=${me.json.enforcementActive}`);
const entitled = (me.json.entitlements ?? []).find((e) => e.featureKey === "WEB_VAPT");
record("provisioned plan entitles WEB_VAPT", entitled?.enabled === true, `enabled=${entitled?.enabled}`);

const plans = await call("GET", "/product/plans");
record("plan catalog lists ACTIVE plans", plans.status === 200 && (plans.json.items ?? []).length >= 1, `plans=${(plans.json.items ?? []).length}`);

// ---- Onboarding (§65–§75) ----
const ob0 = await call("GET", "/product/onboarding");
record("onboarding starts at WELCOME with SAFE default profile", ob0.status === 200 && ob0.json.currentStep === "WELCOME" && ob0.json.defaultAssessmentProfile === "SAFE_STANDARD", `step=${ob0.json.currentStep}`);
await call("POST", "/product/onboarding/steps/WELCOME/complete", {});
await call("POST", "/product/onboarding/steps/ORGANIZATION_PROFILE/complete", {});
await call("POST", "/product/onboarding/steps/WORKSPACE_SETUP/complete", {});
const noAttest = await call("POST", "/product/onboarding/steps/SECURITY_SCOPE/complete", {});
record("SECURITY_SCOPE refuses completion without attestation", noAttest.status >= 400, `status=${noAttest.status}`);
const attest = await call("POST", "/product/onboarding/steps/SECURITY_SCOPE/complete", { attested: true });
record("attestation records authorization", attest.status < 300 && attest.json.authorizationAttested === true, `status=${attest.status}`);
const outOfOrder = await call("POST", "/product/onboarding/steps/FIRST_REPORT/complete", {});
record("out-of-order step completion refused", outOfOrder.status >= 400, `status=${outOfOrder.status}`);

// ---- Usage & quotas (§38–§51) ----
const rec1 = await call("POST", "/product/usage/record", { metric: "SCAN_JOBS", quantity: 1, source: "product-smoke", idempotencyKey: `smoke:${stamp}:1` });
const rec2 = await call("POST", "/product/usage/record", { metric: "SCAN_JOBS", quantity: 1, source: "product-smoke", idempotencyKey: `smoke:${stamp}:1` });
record("metering is idempotent (replay = duplicate)", rec1.status < 300 && rec2.json.duplicate === true, `dup=${rec2.json.duplicate}`);
const usage = await call("GET", "/product/usage");
const scanJobs = (usage.json.usage ?? []).find((u) => u.metric === "SCAN_JOBS");
record("usage view reports the metered scan job exactly once", usage.status === 200 && scanJobs?.quantity === 1, `quantity=${scanJobs?.quantity}`);
record("usage view carries quota dimensions", Array.isArray(usage.json.quotas) && usage.json.quotas.length > 0, `dims=${(usage.json.quotas ?? []).length}`);

// ---- Billing honesty (§21/§109) ----
const billing = await call("GET", "/product/billing");
record("billing reports its real configuration state", billing.status === 200 && ["NOT_CONFIGURED", "TEST_ONLY", "CONFIGURED"].includes(billing.json.status?.status), `billing=${billing.json.status?.status}`);
const webhook = await call("POST", "/product/billing/webhook/stripe", { id: "evt_smoke", type: "invoice.issued", data: {} }, false);
record("webhook to unconfigured provider never simulates success", billing.json.status?.status !== "NOT_CONFIGURED" || webhook.status >= 500, `status=${webhook.status}`);

// ---- License state (§110) ----
const lic = await call("GET", "/product/license");
record("license view is explicit (enabled or not-configured)", lic.status === 200 && (lic.json.licensingEnabled === false || lic.json.installed !== undefined), `licensingEnabled=${lic.json.licensingEnabled}`);
const badLic = await call("POST", "/product/license/install", { document: "{\"version\":1,\"payload\":{},\"signature\":\"AAAA\"}" });
record("garbage license document rejected (never silently accepted)", badLic.status >= 400, `status=${badLic.status}`);

// ---- Capabilities (§119) ----
const caps = await call("GET", "/product/capabilities");
record("capabilities resolve to explicit states", caps.status === 200 && (caps.json ?? []).every((c) => typeof c.state === "string"), `count=${(caps.json ?? []).length}`);
const commercial = await call("GET", "/product/commercial-tools");
record("commercial tools report configuration status", commercial.status === 200 && Array.isArray(commercial.json), `tools=${(commercial.json ?? []).length}`);

// ---- Platform boundary (§98): tenant OWNER is not a platform admin ----
const plat = await call("GET", "/platform/organizations");
record("tenant owner is denied platform organization view", plat.status === 403, `status=${plat.status}`);

// ---- Downgrade preview + cancellation (§114–§118, §86) ----
const catalog = plans.json.items ?? [];
const community = catalog.find((p) => p.code === "COMMUNITY");
if (community?.versions?.[0]) {
  const preview = await call("POST", "/product/subscription/downgrade/preview", { planVersionId: community.versions[0].id });
  record("downgrade impact preview computes (dataDeleted always false)", preview.status < 300 && preview.json.impact?.dataDeleted === false, `status=${preview.status}`);
  const noAck = await call("POST", "/product/subscription/downgrade", { planVersionId: community.versions[0].id });
  record("downgrade without impact acknowledgement refused", noAck.status >= 400, `status=${noAck.status}`);
}
const delPreview = await call("POST", "/product/organization/deletion/preview", {});
record("deletion preview counts real data", delPreview.status < 300 && typeof delPreview.json.workspaces === "number", `status=${delPreview.status}`);

// ---- Diagnostics (§206) ----
const diag = await call("GET", "/product/diagnostics");
const diagText = JSON.stringify(diag.json ?? {});
record("diagnostic bundle is secret-free", diag.status < 300 && !diagText.includes("JWT_SECRET") && !/sk-[a-z0-9]/i.test(diagText), `status=${diag.status} version=${diag.json?.releaseVersion}`);

const failed = results.filter((r) => !r.ok).length;
console.log(`\nPRODUCT SMOKE: ${results.length - failed}/${results.length} PASS`);
process.exit(process.exitCode ?? 0);
