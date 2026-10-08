#!/usr/bin/env node
/**
 * DSRclone Prompt 38 live platform-operations smoke.
 * Exercises the REAL V2 operations surface against the running stack:
 * health incl. MinIO -> register -> platform overview/config/queues/
 * workers -> kill switch without confirmation (refused) -> with
 * confirmation (engaged) -> governed scan start BLOCKED by the kill
 * switch -> kill switch off -> scan starts -> real encrypted pg_dump
 * backup -> restore refusals (bad confirmation, production target) ->
 * isolated restore with recorded validation -> SLOs (measured backup
 * SLO + INSUFFICIENT_DATA availability) -> deployment record.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/platform-ops-smoke.mjs
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
record("health ok + object storage ok (MinIO provisioned)",
  health.status < 300 && health.json.checks?.minio?.status === "ok",
  `status=${health.json.status} minio=${health.json.checks?.minio?.status}`);

const reg = await call("POST", "/auth/register",
  { email: `platform-${stamp}@example.com`, password: PASSWORD, name: "Platform Smoke", organizationName: `Platform Org ${stamp}` }, false);
token = reg.json.accessToken ?? "";
record("register owner", reg.status < 300 && !!token, `status=${reg.status}`);

const overview = await call("GET", "/platform/overview");
record("platform overview", overview.status === 200 && !!overview.json.control,
  `status=${overview.status} platform=${overview.json.status} storage=${overview.json.storage?.status}`);

const cfg = await call("GET", "/platform/config/validation");
record("production config evaluation (dev mode honest)", cfg.status === 200 && cfg.json.mode === "development",
  `mode=${cfg.json.mode} ok=${cfg.json.ok}`);

const queues = await call("GET", "/platform/queues");
record("queue admin snapshot", queues.status === 200 && Array.isArray(queues.json.items) && queues.json.items.length >= 3,
  `queues=${queues.json.items?.length}`);

const workers = await call("GET", "/platform/workers");
record("worker admin list", workers.status === 200 && Array.isArray(workers.json.items), `workers=${workers.json.items?.length}`);

const noConfirm = await call("POST", "/platform/control/kill-switch", { switch: "SCAN_STARTS", enabled: true });
record("kill switch without confirmation refused (§202)", noConfirm.status === 400, `status=${noConfirm.status}`);

const engaged = await call("POST", "/platform/control/kill-switch",
  { switch: "SCAN_STARTS", enabled: true, reason: "platform smoke drill", confirm: true });
record("kill switch engaged with confirmation", engaged.status === 201 || engaged.status === 200,
  `switches=${JSON.stringify(engaged.json.killSwitches ?? {})}`);

// Governed chain up to scan start — the kill switch must bite first.
const target = await call("POST", "/targets", { name: "Example (fixture)", type: "DOMAIN", value: "example.com" });
const ver = await call("POST", `/targets/${target.json.id}/verifications`, { method: "MANUAL_APPROVAL" });
await call("POST", `/targets/${target.json.id}/verifications/${ver.json.verification?.id}/check`, {});
const scope = await call("POST", "/scopes", { targetId: target.json.id, name: "example.com only", rules: { includeHosts: ["example.com"] } });
const assessment = await call("POST", "/assessments",
  { name: "Platform PASSIVE_RECON", targetId: target.json.id, scopeId: scope.json.id, profile: "PASSIVE_RECON" });
await call("POST", `/assessments/${assessment.json.id}/approve`, {});
const blocked = await call("POST", `/assessments/${assessment.json.id}/scans`, {});
record("scan start BLOCKED by SCAN_STARTS kill switch (§158)",
  blocked.status === 400 && JSON.stringify(blocked.json).includes("PLATFORM_WORK_BLOCKED"),
  `status=${blocked.status}`);

const disengaged = await call("POST", "/platform/control/kill-switch",
  { switch: "SCAN_STARTS", enabled: false, confirm: true });
record("kill switch disengaged", (disengaged.status === 201 || disengaged.status === 200), `status=${disengaged.status}`);

const scan = await call("POST", `/assessments/${assessment.json.id}/scans`, {});
record("scan starts once the switch is off", scan.status < 300, `status=${scan.status} scan=${scan.json.id ?? "?"}`);

const backup = await call("POST", "/platform/backups", { kind: "POSTGRES" });
record("real encrypted backup completes (§160/§166)",
  (backup.status === 201 || backup.status === 200) && backup.json.status === "COMPLETED" &&
  backup.json.encrypted === true && typeof backup.json.checksumSha256 === "string" && backup.json.checksumSha256.length === 64,
  `status=${backup.json.status} size=${backup.json.sizeBytes} encrypted=${backup.json.encrypted}`);
const backupId = backup.json.id;

const badConfirm = await call("POST", `/platform/backups/${backupId}/restore`,
  { targetDatabase: "dsrclone_restore", confirm: "yes" });
record("restore with wrong confirmation refused", badConfirm.status === 400, `status=${badConfirm.status}`);

const prodTarget = await call("POST", `/platform/backups/${backupId}/restore`,
  { targetDatabase: "dsrclone", confirm: "RESTORE_INTO_ISOLATED_ENVIRONMENT" });
record("restore over production refused (§173)", prodTarget.status === 400, `status=${prodTarget.status}`);

const restore = await call("POST", `/platform/backups/${backupId}/restore`,
  { targetDatabase: `dsrclone_${stamp}_restore`, confirm: "RESTORE_INTO_ISOLATED_ENVIRONMENT", isRestoreTest: true });
const v = restore.json.validation ?? {};
record("isolated restore completes with §174 validation recorded",
  (restore.status === 201 || restore.status === 200) && restore.json.status === "COMPLETED" &&
  v.databaseConsistent === true && v.objectReferencesValid === true && v.reportAccessValid === true &&
  v.findingHistoryPresent === true && v.tenantIsolationIntact === true,
  `status=${restore.json.status} validation=${JSON.stringify(v)}`);

const restores = await call("GET", `/platform/backups/${backupId}/restores`);
record("restore history listed", restores.status === 200 && restores.json.items?.length >= 1, `restores=${restores.json.items?.length}`);

const slos = await call("GET", "/platform/slos");
const backupSlo = slos.json.items?.find((i) => i.kind === "BACKUP_SUCCESS");
const availSlo = slos.json.items?.find((i) => i.kind === "API_AVAILABILITY");
record("SLOs measured-or-insufficient, never fabricated (§127)",
  slos.status === 200 && backupSlo?.result?.status !== "INSUFFICIENT_DATA" &&
  availSlo?.result?.status === "INSUFFICIENT_DATA" && availSlo?.result?.ratio === null,
  `backup=${backupSlo?.result?.status}(${backupSlo?.result?.ratio}) availability=${availSlo?.result?.status}`);

const deployment = await call("POST", "/platform/deployments",
  { version: "38.0.0-smoke", commit: process.env.GIT_COMMIT ?? "1eb3310", environment: "local-stack" });
record("deployment recorded (§147/§156)", (deployment.status === 201 || deployment.status === 200) && deployment.json.status === "COMPLETED",
  `status=${deployment.status}`);

const after = await call("GET", "/platform/overview");
record("overview reflects the drill", after.status === 200 && after.json.backups?.latest?.status === "COMPLETED",
  `latestBackup=${after.json.backups?.latest?.status} release=${after.json.release?.version}`);

const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} platform-ops smoke checks passed`);
