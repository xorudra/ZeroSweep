#!/usr/bin/env node
/**
 * ZeroSweep live vulnerability-intelligence smoke (Prompt 30).
 *
 * Exercises the P30 layer end-to-end against the running API + live
 * PostgreSQL: register -> login -> provider state (honestly
 * NEVER_SYNCED / NOT_CONFIGURED) -> governed FIXTURE_EXCERPT imports
 * (recorded NVD/EPSS/KEV/GHSA excerpts from the SDK fixture set) ->
 * CVE detail with provenance + preferred CVSS + EPSS history -> KEV
 * catalog transitions -> dashboards -> grounded AI (verbatim no-fix
 * sentence; unknown CVE reports no intelligence) -> live sync attempt
 * honestly NOT_CONFIGURED.
 *
 * Fixture imports are provenance-labelled FIXTURE_EXCERPT and never
 * advance the dataset sync state — the final step re-verifies that.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/vuln-intel-smoke.mjs
 */
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
const require = createRequire(import.meta.url);
const sdk = require(fileURLToPath(new URL("../../packages/security-sdk/dist/index.js", import.meta.url)));

const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `vi-smoke-${stamp}@example.com`;
const PASSWORD = "smoke-password-123";
let token = "";
const results = [];
function record(step, ok, detail) {
  results.push({ step, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${step}${detail ? ` — ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}
async function call(method, path, body, auth = true) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(auth && token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 200) }; }
  return { status: res.status, json };
}

const health = await call("GET", "/health", undefined, false);
record("health (postgres ok)", health.status === 200 && health.json.checks?.postgres?.status === "ok", `postgres=${health.json.checks?.postgres?.status}`);

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "Smoke Operator", organizationName: `VI Smoke Org ${stamp}` }, false);
if (reg.json.accessToken) token = reg.json.accessToken;
record("register", reg.status < 300 && !!token, `status=${reg.status}`);
const login = await call("POST", "/auth/login", { email: EMAIL, password: PASSWORD }, false);
if (login.json.accessToken) token = login.json.accessToken;
record("login", login.status < 300 && !!login.json.accessToken, `status=${login.status}`);

const providersBefore = await call("GET", "/vulnerability-intelligence/providers");
const nvdStateBefore = (providersBefore.json.syncStates ?? []).find((s) => s.source === "NVD");
record("providers: live fetch NOT_CONFIGURED, dataset never SYNCED",
  providersBefore.json.liveFetch?.status === "NOT_CONFIGURED" && !!nvdStateBefore && nvdStateBefore.status !== "SYNCED",
  `liveFetch=${providersBefore.json.liveFetch?.status} nvd=${nvdStateBefore?.status ?? "absent"}`);

const nvdImport = await call("POST", "/vulnerability-intelligence/import", { kind: "NVD", provider: "NVD", origin: "FIXTURE_EXCERPT", document: sdk.NVD_FIXTURE_FEED });
record("import recorded NVD excerpt (fixture-scoped)",
  nvdImport.status < 300 && nvdImport.json.parsed === 3 && nvdImport.json.rejected?.length >= 1 && !!nvdImport.json.checksum,
  `parsed=${nvdImport.json.parsed} rejected=${nvdImport.json.rejected?.length} checksum=${String(nvdImport.json.checksum ?? "").slice(0, 12)}…`);

const epss1 = await call("POST", "/vulnerability-intelligence/import", { kind: "EPSS", provider: "FIRST_EPSS", origin: "FIXTURE_EXCERPT", document: sdk.EPSS_FIXTURE_CSV_DAY1 });
const epss2 = await call("POST", "/vulnerability-intelligence/import", { kind: "EPSS", provider: "FIRST_EPSS", origin: "FIXTURE_EXCERPT", document: sdk.EPSS_FIXTURE_CSV_DAY2 });
record("import EPSS day 1 + day 2 excerpts", epss1.json.parsed === 2 && epss2.json.parsed === 2, `day1=${epss1.json.parsed} day2=${epss2.json.parsed}`);

const advisory = await call("POST", "/vulnerability-intelligence/import", { kind: "ADVISORY", provider: "GHSA", origin: "FIXTURE_EXCERPT", document: sdk.ADVISORY_FIXTURE });
record("import GHSA advisory excerpt -> patch records", advisory.status < 300 && advisory.json.patchRecords >= 1, `patchRecords=${advisory.json.patchRecords}`);

const detail = await call("GET", "/vulnerability-intelligence/cves/CVE-2021-44228");
record("CVE detail: preferred CVSS 10.0 (NVD), EPSS history of 2, fixture provenance",
  detail.json.preferredCvss?.baseScore === 10.0 && detail.json.preferredCvss?.source === "NVD"
    && detail.json.epssPoints?.length === 2 && detail.json.epssCurrent?.score === 0.975
    && detail.json.provenance?.snapshotOrigin === "FIXTURE_EXCERPT",
  `cvss=${detail.json.preferredCvss?.baseScore}/${detail.json.preferredCvss?.source} epssPoints=${detail.json.epssPoints?.length} current=${detail.json.epssCurrent?.score}`);

const kev1 = await call("POST", "/vulnerability-intelligence/import", { kind: "KEV", provider: "CISA_KEV", origin: "FIXTURE_EXCERPT", document: sdk.KEV_FIXTURE_CATALOG_1, fullCatalog: true });
const detailAfterKev = await call("GET", "/vulnerability-intelligence/cves/CVE-2021-44228");
record("KEV catalog 1: CVE-2021-44228 KEV-listed afterwards",
  kev1.status < 300 && detailAfterKev.json.kevListed === true && detailAfterKev.json.kev?.status === "ACTIVE",
  `transitions=${JSON.stringify(kev1.json.transitions)} kevListed=${detailAfterKev.json.kevListed}`);
const kev2 = await call("POST", "/vulnerability-intelligence/import", { kind: "KEV", provider: "CISA_KEV", origin: "FIXTURE_EXCERPT", document: sdk.KEV_FIXTURE_CATALOG_2, fullCatalog: true });
record("KEV catalog 2: CVE-2023-44487 ADDED (transition event)",
  kev2.status < 300 && (kev2.json.transitions ?? []).some((t) => t.cveId === "CVE-2023-44487" && t.type === "ADDED"),
  `transitions=${JSON.stringify(kev2.json.transitions)}`);

const kevDash = await call("GET", "/vulnerability-intelligence/kev");
record("KEV dashboard: 2 catalog entries + ADDED events visible",
  kevDash.json.totalKevCatalog === 2 && (kevDash.json.recentEvents ?? []).some((e) => e.cveId === "CVE-2023-44487" && e.eventType === "ADDED"),
  `catalog=${kevDash.json.totalKevCatalog} events=${(kevDash.json.recentEvents ?? []).length}`);

const noFix = await call("POST", "/vulnerability-intelligence/ask", { question: "How do I fix CVE-2023-44487?" });
record("AI: mitigation-only CVE gets the verbatim no-fix sentence",
  typeof noFix.json.answer === "string" && noFix.json.answer.includes("No verified fix is currently recorded.") && noFix.json.executed === false,
  `answer="${String(noFix.json.answer ?? "").slice(0, 80)}…"`);

const unknown = await call("GET", "/vulnerability-intelligence/cves/CVE-1999-0001");
record("unknown CVE: no intelligence reported (never invented)",
  unknown.status < 300 && !!unknown.json.noIntelligence && unknown.json.epssCurrent === undefined,
  `note=${String(unknown.json.noIntelligence ?? "").slice(0, 60)}…`);

const providersMid = await call("GET", "/vulnerability-intelligence/providers");
const nvdStateMid = (providersMid.json.syncStates ?? []).find((s) => s.source === "NVD");
record("fixture imports did NOT move the sync state (fixture never masquerades as production sync)",
  !!nvdStateMid && !!nvdStateBefore && nvdStateMid.status === nvdStateBefore.status,
  `before=${nvdStateBefore?.status} after-imports=${nvdStateMid?.status}`);

const sync = await call("POST", "/vulnerability-intelligence/sync", { provider: "NVD" });
record("live sync attempt: honestly NOT_CONFIGURED", sync.status < 300 && sync.json.status === "NOT_CONFIGURED", `status=${sync.json.status}`);

const providersAfter = await call("GET", "/vulnerability-intelligence/providers");
const nvdStateAfter = (providersAfter.json.syncStates ?? []).find((s) => s.source === "NVD");
record("the sync ATTEMPT is recorded as FAILED with its reason — never as success",
  !!nvdStateAfter && nvdStateAfter.status === "FAILED" && String(nvdStateAfter.detail ?? "").includes("no egress fetcher"),
  `nvd=${nvdStateAfter?.status} detail=${String(nvdStateAfter?.detail ?? "").slice(0, 40)}…`);

const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} vuln-intel smoke steps passed`);
