#!/usr/bin/env node
/**
 * DSRclone RC1 release gates (Prompt 39 §285–§298).
 *
 * Every gate is MANDATORY for an RC_READY verdict. A gate that cannot
 * run (e.g. live stack down) FAILS — it never silently passes. Results
 * are written to release/rc1/test-results/release-gates.json.
 *
 * Usage: node scripts/release/check-rc1.mjs [--skip-slow]
 *   --skip-slow skips the backup/restore round-trip gate (Gate 11);
 *   the gate is then recorded as FAIL with reason "skipped by operator"
 *   so a skipped run can never be mistaken for an RC_READY run.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const ROOT = process.cwd();
const skipSlow = process.argv.includes("--skip-slow");
const gates = [];

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", timeout: opts.timeout ?? 1_200_000, env: { ...process.env, ...(opts.env ?? {}) } });
  return { code: r.status ?? 1, out: `${r.stdout ?? ""}\n${r.stderr ?? ""}` };
}
function gate(n, name, ok, detail) {
  gates.push({ gate: n, name, status: ok ? "PASS" : "FAIL", detail: String(detail).slice(0, 400) });
  console.log(`${ok ? "PASS" : "FAIL"}  Gate ${n}: ${name} — ${String(detail).slice(0, 160)}`);
}
const PNPM = ["pnpm@9.15.0"];

// Gate 1 — BUILD (§286)
{
  const r = run("npx", [...PNPM, "build"]);
  gate(1, "BUILD", r.code === 0, r.code === 0 ? "turbo build green" : r.out.slice(-300));
}
// Gate 2 — LINT/TYPECHECK (§287)
{
  const tc = run("npx", [...PNPM, "typecheck"]);
  const lint = run("npx", [...PNPM, "lint"]);
  gate(2, "LINT/TYPECHECK", tc.code === 0 && lint.code === 0, `typecheck=${tc.code} lint=${lint.code}`);
}
// Gate 3 — UNIT/INTEGRATION (§288)
let testSummary = "";
{
  const r = run("npx", [...PNPM, "turbo", "run", "test", "--force"]);
  const pyRun = spawnSync("python3", ["-m", "pytest", "-q"], { cwd: join(ROOT, "apps/ai"), encoding: "utf8", timeout: 300_000 });
  const tsMatch = r.out.match(/Tasks:\s+(\d+) successful, (\d+) total/);
  testSummary = tsMatch ? `turbo ${tsMatch[1]}/${tsMatch[2]} tasks` : "turbo summary not found";
  gate(3, "UNIT/INTEGRATION", r.code === 0 && pyRun.status === 0, `${testSummary}; pytest exit=${pyRun.status}`);
}
// Gate 4 — TENANT ISOLATION (§289): dedicated suite + live matrix is Gate 7
{
  const r = spawnSync("npx", ["jest", "src/modules/release/tenant-isolation.spec.ts", "--runInBand"], { cwd: join(ROOT, "apps/api"), encoding: "utf8", timeout: 300_000 });
  const m = r.stdout?.match(/Tests:\s+(\d+) passed/);
  gate(4, "TENANT ISOLATION", r.status === 0, m ? `${m[1]} TenantIsolationTestSuite tests passed` : (r.stdout ?? "").slice(-200));
}
// Gate 5 — AUTHORIZATION (§290): policy engine + scope/target/orchestration specs
{
  const sdk = spawnSync("npx", ["vitest", "run", "src/policy"], { cwd: join(ROOT, "packages/security-sdk"), encoding: "utf8", timeout: 300_000 });
  const api = spawnSync("npx", ["jest", "src/modules/targets", "src/modules/orchestration", "src/modules/scanners", "--runInBand"], { cwd: join(ROOT, "apps/api"), encoding: "utf8", timeout: 600_000 });
  gate(5, "AUTHORIZATION", sdk.status === 0 && api.status === 0, `sdk policy=${sdk.status} api authz suites=${api.status}`);
}
// Gate 6 — SCANNER SAFETY (§291): SDK suites + structural invariants
{
  const sdk = spawnSync("npx", ["vitest", "run", "src/policy", "src/recon", "src/release"], { cwd: join(ROOT, "packages/security-sdk"), encoding: "utf8", timeout: 600_000 });
  let shellTrue = 0;
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === "dist") continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".ts") && !e.name.includes(".spec.")) {
        if (/shell\s*:\s*true/.test(readFileSync(p, "utf8"))) shellTrue++;
      }
    }
  };
  walk(join(ROOT, "apps")); walk(join(ROOT, "packages"));
  gate(6, "SCANNER SAFETY", sdk.status === 0 && shellTrue === 0, `sdk suites=${sdk.status}; shell:true occurrences=${shellTrue}`);
}
// Gate 7 — E2E CORE FLOW (§292) + Gate 8 — REPORT/CLIENT ISOLATION (§293)
{
  let healthOk = false;
  try {
    const res = await fetch("http://127.0.0.1:4000/api/v1/health");
    const j = await res.json();
    healthOk = res.status === 200 && j.status === "ok";
  } catch { healthOk = false; }
  if (!healthOk) {
    gate(7, "E2E CORE FLOW", false, "live stack health is not ok — gate cannot run");
    gate(8, "REPORT/CLIENT ISOLATION", false, "live stack health is not ok — gate cannot run");
  } else {
    const out = join(ROOT, "release/rc1/test-results/e2e-results.json");
    const r = run("node", ["tests/e2e/run-e2e.mjs"], { env: { E2E_RESULTS_PATH: out } });
    let suites = {};
    try { const s = JSON.parse(readFileSync(out, "utf8")); for (const x of s.results) suites[x.suite] = (suites[x.suite] ?? true) && x.ok; } catch { /* handled below */ }
    gate(7, "E2E CORE FLOW", r.code === 0 && suites["core-flow"] === true, `e2e exit=${r.code}`);
    gate(8, "REPORT/CLIENT ISOLATION", suites["client-isolation"] === true && suites["tenant-isolation"] === true,
      `client=${suites["client-isolation"]} tenant=${suites["tenant-isolation"]}`);
  }
}
// Gate 9 — AI SECURITY (§294)
{
  const sdk = spawnSync("npx", ["vitest", "run", "src/ai"], { cwd: join(ROOT, "packages/security-sdk"), encoding: "utf8", timeout: 300_000 });
  const py = spawnSync("python3", ["-m", "pytest", "-q"], { cwd: join(ROOT, "apps/ai"), encoding: "utf8", timeout: 300_000 });
  gate(9, "AI SECURITY", sdk.status === 0 && py.status === 0, `sdk ai=${sdk.status} pytest=${py.status}`);
}
// Gate 10 — SECRET SCAN (§295): tracked files. Canaries are handled by
// VALUE, not by file: AWS-shaped tokens containing FAKE or EXAMPLE are
// planted test canaries (incl. AWS's published documentation example
// key) whose non-leakage the suites assert; any other AWS-shaped token
// fails. Private keys count only as a FULL block (BEGIN + body + END):
// a bare BEGIN string is a detection signature in the secret scanners
// or a dummy literal in a spec — a leaked real key always has a body.
{
  const files = execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).split("\n").filter(Boolean);
  let hits = 0; const examples = [];
  const hit = (f, what) => { hits++; if (examples.length < 5) examples.push(`${f}: ${what}`); };
  for (const f of files) {
    if (f.endsWith("pnpm-lock.yaml") || f.includes("release/rc1/")) continue;
    let text; try { text = readFileSync(join(ROOT, f), "utf8"); } catch { continue; }
    const isTestFile = /\.spec\.tsx?$|fixtures/.test(f);
    for (const m of text.matchAll(/AKIA[0-9A-Z]{16}/g)) {
      if (!/FAKE|EXAMPLE/.test(m[0])) hit(f, `AWS-shaped token ${m[0].slice(0, 8)}…`);
    }
    // Token-shaped values are canaries only inside test files (the
    // redaction suites plant synthetic tokens to prove scrubbing);
    // anywhere else they fail closed.
    if (!isTestFile) {
      for (const m of text.matchAll(/ghp_[0-9A-Za-z]{36}/g)) hit(f, "GitHub PAT-shaped token");
      for (const m of text.matchAll(/sk-[0-9A-Za-z]{32,}/g)) hit(f, "sk- token");
      for (const m of text.matchAll(/xox[baprs]-[0-9A-Za-z-]{10,}/g)) hit(f, "Slack token");
    }
    for (const m of text.matchAll(/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{0,2000}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g)) {
      // Full blocks pass only with a recognized dummy body — the exact
      // synthetic key material the redaction/validation suites plant
      // (MIIFixture…, MIIxyz, MIIBog==, or the literal "abc"). A real
      // key body matches none of these and fails.
      const body = m[0].replace(/-----BEGIN[^]*?-----|-----END[^]*?-----/g, "").replace(/\\n/g, "").trim();
      if (!(body === "abc" || /fixture/i.test(body) || body === "MIIxyz" || body === "MIIBog==")) {
        hit(f, "full private-key block with non-dummy body");
      }
    }
  }
  gate(10, "SECRET SCAN", hits === 0, hits === 0 ? "no non-canary secret patterns in tracked files" : examples.join("; "));
}
// Gate 11 — BACKUP/RESTORE (§296): pg_dump/pg_restore round-trip on scratch DBs
{
  if (skipSlow) {
    gate(11, "BACKUP/RESTORE", false, "skipped by operator (--skip-slow) — an RC run must not skip this gate");
  } else {
    const stack = join(process.env.HOME ?? "", "workspace/dsrclone-local-stack");
    const pgBin = join(stack, "venv/lib/python3.12/site-packages/pgserver/pginstall/bin");
    const dump = join(stack, "backups/rc1-gate.dump");
    const env = { ...process.env };
    const steps = [
      ["psql", ["-h", "127.0.0.1", "-p", "54329", "-U", "dsrclone", "-d", "postgres", "-c", "DROP DATABASE IF EXISTS dsrclone_rc1_gate;"]],
      ["pg_dump", ["-h", "127.0.0.1", "-p", "54329", "-U", "dsrclone", "-Fc", "-f", dump, "dsrclone"]],
      ["psql", ["-h", "127.0.0.1", "-p", "54329", "-U", "dsrclone", "-d", "postgres", "-c", "CREATE DATABASE dsrclone_rc1_gate;"]],
      ["pg_restore", ["-h", "127.0.0.1", "-p", "54329", "-U", "dsrclone", "-d", "dsrclone_rc1_gate", dump]],
    ];
    let ok = true; let detail = "";
    for (const [bin, args] of steps) {
      const r = spawnSync(join(pgBin, bin), args, { encoding: "utf8", timeout: 600_000, env });
      if (r.status !== 0) { ok = false; detail = `${bin} failed: ${(r.stderr ?? "").slice(0, 150)}`; break; }
    }
    if (ok) {
      const q = (db) => spawnSync(join(pgBin, "psql"), ["-h", "127.0.0.1", "-p", "54329", "-U", "dsrclone", "-d", db, "-Atc", "SELECT (SELECT count(*) FROM \"Finding\") || '/' || (SELECT count(*) FROM \"AuditLog\");"], { encoding: "utf8" }).stdout?.trim();
      const a = q("dsrclone"); const b = q("dsrclone_rc1_gate");
      ok = a === b && !!a;
      detail = `findings/audit source=${a} restored=${b}`;
      spawnSync(join(pgBin, "psql"), ["-h", "127.0.0.1", "-p", "54329", "-U", "dsrclone", "-d", "postgres", "-c", "DROP DATABASE IF EXISTS dsrclone_rc1_gate;"], { encoding: "utf8" });
    }
    gate(11, "BACKUP/RESTORE", ok, detail);
  }
}
// Gate 12 — PRODUCTION CONFIGURATION (§297)
{
  const compose = readFileSync(join(ROOT, "deploy/compose/docker-compose.production.yml"), "utf8");
  const checks = {
    readOnly: /read_only:\s*true/.test(compose),
    capDropAll: /cap_drop:\s*\["ALL"\]/.test(compose),
    noNewPrivileges: /no-new-privileges/.test(compose),
    immutableTags: /\$\{DSRCLONE_VERSION:\?/.test(compose),
    stagedCiPresent: (() => { try { readFileSync(join(ROOT, "deploy/ci/production-ci.yml"), "utf8"); return true; } catch { return false; } })(),
    webSecurityHeaders: /Content-Security-Policy/.test(readFileSync(join(ROOT, "apps/web/next.config.mjs"), "utf8")),
  };
  const failed = Object.entries(checks).filter(([, v]) => !v).map(([k]) => k);
  gate(12, "PRODUCTION CONFIGURATION", failed.length === 0, failed.length ? `missing: ${failed.join(",")}` : "compose hardening + staged CI present");
}
// Gate 13 — NO BLOCKER RELEASE FINDINGS (§298)
{
  let blockers = -1;
  try {
    const doc = readFileSync(join(ROOT, "docs/release/rc1-findings.md"), "utf8");
    blockers = (doc.match(/RC1-B\d+[^|\n]*\|[^|\n]*OPEN/g) ?? []).length;
  } catch { blockers = -1; }
  gate(13, "NO BLOCKER RELEASE FINDINGS", blockers === 0, blockers === 0 ? "no OPEN blockers in rc1-findings.md" : `open blockers=${blockers}`);
}

const verdict = gates.every((g) => g.status === "PASS") ? "RC_READY" : "RC_BLOCKED";
const summary = { release: "DSRclone RC1", version: "1.0.0-rc.1", generatedAt: new Date().toISOString(), verdict, testSummary, gates };
writeFileSync(join(ROOT, "release/rc1/test-results/release-gates.json"), JSON.stringify(summary, null, 2));
console.log(`\nRC1 verdict: ${verdict} (${gates.filter((g) => g.status === "PASS").length}/${gates.length} gates PASS)`);
process.exit(verdict === "RC_READY" ? 0 : 1);
