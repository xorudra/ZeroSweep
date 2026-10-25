import { describe, expect, it } from "vitest";
import {
  FIXTURE_BANDIT_OUTPUT, FIXTURE_BRAKEMAN_OUTPUT, FIXTURE_CODEQL_SARIF, FIXTURE_FAKE_AWS_KEY,
  FIXTURE_FAKE_PASSWORD, FIXTURE_GITLEAKS_OUTPUT, FIXTURE_GRYPE_OUTPUT, FIXTURE_SEMGREP_OUTPUT,
  FIXTURE_TRUFFLEHOG_OUTPUT, FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  codeHealthBySlug, createCodeAdapters, type FixtureResponse,
} from "@zerosweep/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 12 end-to-end scenarios (§100–§109): the real source-security
 * adapters run the full pipeline against the SDK fixture repository and
 * RECORDED tool outputs. No binary executes, no network is touched, and
 * the fixture repository's hostile package.json lifecycle scripts are
 * NEVER run — the runner's call log proves only analyzer binaries were
 * invoked (§108). Fake secrets embedded in the fixture outputs must
 * appear NOWHERE in persisted state (§101).
 */

type SourceProfile = "SOURCE_BASELINE" | "SECRETS_ONLY" | "SAST_ONLY";

function baselineFixtures(): Record<string, FixtureResponse> {
  return {
    semgrep: { stdout: FIXTURE_SEMGREP_OUTPUT, version: "1.95.0" },
    bandit: { stdout: FIXTURE_BANDIT_OUTPUT, version: "1.8.6" },
    brakeman: { stdout: FIXTURE_BRAKEMAN_OUTPUT, version: "7.0.2" },
    gitleaks: { stdout: FIXTURE_GITLEAKS_OUTPUT, version: "8.24.2" },
    trufflehog: { stdout: FIXTURE_TRUFFLEHOG_OUTPUT, version: "3.88.0" },
    grype: { stdout: FIXTURE_GRYPE_OUTPUT, version: "0.92.0" },
  };
}

function makeWorld(fixtures: Record<string, FixtureResponse>, profile: SourceProfile) {
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  const planAdapters = createCodeAdapters(new FixtureToolRunner(fixtures));
  for (const a of planAdapters) planRegistry.register(a);
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: codeHealthBySlug(planAdapters),
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "SOURCE_REPOSITORY",
  });
  const runner = new FixtureToolRunner(fixtures);
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createCodeAdapters(runner)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store);
  return { runner, store, dag: new DagRunner(store, executor) };
}

describe("Prompt 12 source security E2E — SOURCE_BASELINE over the fixture repository", () => {
  it("completes the full source pipeline: snapshot → detection → SAST/secrets/SCA → SBOM → quality gate", async () => {
    const { runner, store, dag } = makeWorld(baselineFixtures(), "SOURCE_BASELINE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect([...store.stages.values()].every((s) => s === "COMPLETED")).toBe(true);

    // Snapshot + detection + inventory platform stages did real work.
    expect(store.sourceSnapshot).not.toBeNull();
    expect(store.events.some((e) => e.type === "source.snapshot_created")).toBe(true);
    expect(store.events.some((e) => e.type === "source.languages_detected")).toBe(true);
    expect(store.events.some((e) => e.type === "source.dependencies_inventoried")).toBe(true);
    expect(store.events.some((e) => e.type === "source.sbom_generated")).toBe(true);
    expect(store.events.some((e) => e.type === "source.scan_completed")).toBe(true);
    expect(store.sbomRecord?.componentCount).toBeGreaterThan(0);

    // Component inventory spans the fixture ecosystems (npm lockfile,
    // Maven, Python, Ruby) — PURL-keyed, one row per component.
    const purls = store.components.map((c) => c.purl);
    expect(purls.some((p) => p.startsWith("pkg:npm/lodash@"))).toBe(true);
    expect(purls.some((p) => p.includes("log4j-core"))).toBe(true);
    expect(purls.some((p) => p.startsWith("pkg:pypi/flask@"))).toBe(true);
    expect(new Set(purls).size).toBe(purls.length);

    // Executed tools are exactly the baseline-governed set.
    const executedSlugs = [...store.executions.values()].map((e) => e.adapterSlug);
    for (const slug of ["semgrep", "bandit", "brakeman", "gitleaks", "trufflehog", "grype"]) {
      expect(executedSlugs).toContain(slug);
    }
    expect(executedSlugs).not.toContain("codeql");
    expect(executedSlugs).not.toContain("dependency-check");

    // §108: the hostile fixture repository was NEVER executed — only
    // analyzer binaries ran; no shell, no package manager, no git, and
    // no invocation mentions the hostile lifecycle script or its URL.
    const calledExecutables = new Set(runner.calls.map((c) => c.executable));
    for (const banned of ["npm", "npx", "node", "make", "sh", "bash", "git", "pip", "curl"]) {
      expect(calledExecutables.has(banned)).toBe(false);
    }
    const allArgs = runner.calls.flatMap((c) => c.args).join(" ");
    expect(allArgs).not.toContain("evil.invalid");
    expect(allArgs).not.toContain("preinstall");

    const canonical = store.correlatedFindings;
    expect(canonical.length).toBeGreaterThan(0);

    // The fake AWS key was reported by BOTH secret scanners and merged
    // into ONE canonical finding carrying both provenances (§66/§103).
    const secrets = canonical.filter((f) => f.secret);
    const awsSecret = secrets.find((f) => f.filePath === "config/aws-credentials.txt");
    expect(awsSecret).toBeDefined();
    expect(awsSecret!.sources).toEqual(expect.arrayContaining(["gitleaks", "trufflehog"]));
    expect(awsSecret!.secret!.redactedPreview).toBe("AKIA…MPLE");
    expect(store.events.some((e) => e.type === "source.secret_detected")).toBe(true);

    // SAST findings from three engines landed with code locations.
    expect(canonical.some((f) => f.cwe === "CWE-78" && f.filePath === "app/main.py")).toBe(true);
    expect(canonical.some((f) => f.cwe === "CWE-89" && f.filePath === "app.rb")).toBe(true);

    // SCA: the Grype log4j + lodash findings carry component identity
    // and trusted fixed versions (§58/§74).
    const log4j = canonical.find((f) => f.cve === "CVE-2021-44228");
    expect(log4j).toBeDefined();
    expect(log4j!.componentPurl).toContain("log4j-core");
    expect(log4j!.fixedVersion).toBe("2.15.0");
    expect(canonical.some((f) => f.cve === "CVE-2021-23337")).toBe(true);
    expect(store.events.some((e) => e.type === "source.dependency_vulnerability_detected")).toBe(true);

    // Quality gate (§81/§82): a verified-format secret + criticals fail
    // the gate; the verdict is recorded, the scan itself completed.
    expect(store.qualityGateRecord?.status).toBe("FAILED");
    expect(store.events.some((e) => e.type === "source.quality_gate_evaluated")).toBe(true);

    // §101: the raw fake secrets appear NOWHERE — not in findings,
    // evidence, components, events or the SBOM record.
    const everything = JSON.stringify({
      findings: store.findings, canonical: store.correlatedFindings,
      events: store.events, components: store.components, sbom: store.sbomRecord,
    });
    expect(everything).not.toContain(FIXTURE_FAKE_AWS_KEY);
    expect(everything).not.toContain(FIXTURE_FAKE_PASSWORD);
  });

  it("SECRETS_ONLY runs only the secret stage and finds only secrets (§18)", async () => {
    const fixtures = {
      gitleaks: { stdout: FIXTURE_GITLEAKS_OUTPUT, version: "8.24.2" },
      trufflehog: { stdout: FIXTURE_TRUFFLEHOG_OUTPUT, version: "3.88.0" },
    };
    const { store, dag } = makeWorld(fixtures, "SECRETS_ONLY");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    const executedSlugs = [...store.executions.values()].map((e) => e.adapterSlug);
    expect(executedSlugs).toEqual(expect.arrayContaining(["gitleaks", "trufflehog"]));
    expect(executedSlugs).not.toContain("semgrep");
    expect(executedSlugs).not.toContain("grype");
    expect(store.correlatedFindings.length).toBeGreaterThan(0);
    expect(store.correlatedFindings.every((f) => f.secret)).toBe(true);
  });

  it("SAST_ONLY: Semgrep + CodeQL SARIF observations of the same flaw merge into one canonical finding (§66)", async () => {
    const fixtures = {
      semgrep: { stdout: FIXTURE_SEMGREP_OUTPUT, version: "1.95.0" },
      codeql: { stdout: FIXTURE_CODEQL_SARIF, version: "2.20.0" },
    };
    const { store, dag } = makeWorld(fixtures, "SAST_ONLY");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    const sqli = store.correlatedFindings.filter((f) => f.filePath === "src/db.ts" && f.cwe === "CWE-89");
    expect(sqli).toHaveLength(1);
    expect(sqli[0]!.sources).toEqual(expect.arrayContaining(["semgrep", "codeql"]));
    // Dataflow evidence survived the merge (§63).
    expect(sqli[0]!.codeFlow?.length).toBeGreaterThan(0);
  });
});
