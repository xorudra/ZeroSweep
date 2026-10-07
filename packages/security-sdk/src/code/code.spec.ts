import { describe, expect, it } from "vitest";
import {
  DEFAULT_SOURCE_BUDGET, InMemoryIntelligenceDataset, SecretFingerprintService,
  buildCycloneDxSbom, buildGitClonePlan, buildPurl, buildSpdxSbom,
  classifyBaseline, classifyRepositoryFile, clampSourceBudget, compareVersions,
  componentToCpe, containsSecretValue, correlateSourceFindings,
  createCodeAdapters, createStoredZip, dedupeComponents, detectRepository,
  enrichDependencyFindings, evaluateQualityGate, executionPolicyViolation,
  fixtureIntelligenceDataset, importSarif, isManifestPath, judgeSourceRetest,
  matchComponentsAgainstIntel, mergeDependencyObservations, normalizeRepoPath,
  parseBandit, parseBrakeman, parseDependencyCheck, parseGitleaks, parseGrype,
  parseManifests, parseSemgrep, parseSonarIssues, parseSpotbugs, parseTrufflehog,
  planSourceRetest, redactSecretsInText, redactedPreview, resolveCodeqlPlan,
  resolveSemgrepPacks, sourceFingerprint, summarizeForQualityGate,
  validateArchiveEntries, validateRepositoryUrl, validateZipArchive,
  DEFAULT_QUALITY_GATE_POLICY, DEFAULT_REPOSITORY_EXECUTION_POLICY,
  FIXTURE_BANDIT_OUTPUT, FIXTURE_CODEQL_SARIF, FIXTURE_DEPCHECK_OUTPUT,
  FIXTURE_FAKE_AWS_KEY, FIXTURE_FAKE_PASSWORD, FIXTURE_GITLEAKS_OUTPUT,
  FIXTURE_GRYPE_OUTPUT, FIXTURE_MANIFEST_CONTENTS, FIXTURE_REPOSITORY_KEY,
  FIXTURE_SEMGREP_OUTPUT, FIXTURE_SONAR_OUTPUT, FIXTURE_SOURCE_FILES,
  FIXTURE_SPOTBUGS_OUTPUT, FIXTURE_TRUFFLEHOG_OUTPUT, FIXTURE_BRAKEMAN_OUTPUT,
  type ParserContext,
} from "../index";

const CTX: ParserContext = { repositoryKey: FIXTURE_REPOSITORY_KEY, sourceTool: "test" };
const ctxFor = (tool: string): ParserContext => ({ repositoryKey: FIXTURE_REPOSITORY_KEY, sourceTool: tool });

describe("Prompt 12 — paths & hostile display (§60/§107)", () => {
  it("normalizes repository-relative paths and rejects escapes", () => {
    expect(normalizeRepoPath("src/db.ts")).toBe("src/db.ts");
    expect(normalizeRepoPath("./src/../src/db.ts")).toBe("src/db.ts");
    expect(normalizeRepoPath("src\\win\\path.ts")).toBe("src/win/path.ts");
    expect(normalizeRepoPath("../outside.txt")).toBeNull();
    expect(normalizeRepoPath("/etc/passwd")).toBeNull();
    expect(normalizeRepoPath("C:\\windows\\system32")).toBeNull();
    expect(normalizeRepoPath("a/../../b")).toBeNull();
  });
});

describe("Prompt 12 — secret handling (§39–§44, §101)", () => {
  it("fingerprints are one-way and stable; the raw value never appears", () => {
    const svc = new SecretFingerprintService("test-key");
    const fp = svc.fingerprint(FIXTURE_FAKE_AWS_KEY);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    expect(fp).not.toContain(FIXTURE_FAKE_AWS_KEY);
    expect(svc.fingerprint(FIXTURE_FAKE_AWS_KEY)).toBe(fp);
    expect(svc.matches(FIXTURE_FAKE_AWS_KEY, fp)).toBe(true);
    expect(new SecretFingerprintService().fingerprint(FIXTURE_FAKE_AWS_KEY)).not.toBe(fp); // keyed ≠ unkeyed domain
  });

  it("redacted previews show fragments only for long values", () => {
    expect(redactedPreview(FIXTURE_FAKE_AWS_KEY)).toBe("AKIA…MPLE");
    expect(redactedPreview("short")).toBeUndefined();
  });

  it("redacts secret values out of arbitrary text", () => {
    const text = `aws key ${FIXTURE_FAKE_AWS_KEY} and password = "hunter2-secret" done`;
    const redacted = redactSecretsInText(text);
    expect(redacted).not.toContain(FIXTURE_FAKE_AWS_KEY);
    expect(redacted).not.toContain("hunter2-secret");
    expect(containsSecretValue(text)).toBe(true);
    expect(containsSecretValue(redacted)).toBe(false);
  });

  it("gitleaks parser stores NO raw secret anywhere in the finding", () => {
    const parsed = parseGitleaks(FIXTURE_GITLEAKS_OUTPUT, ctxFor("gitleaks"));
    expect(parsed.findings).toHaveLength(1);
    const serialized = JSON.stringify(parsed.findings);
    expect(serialized).not.toContain(FIXTURE_FAKE_AWS_KEY);
    const f = parsed.findings[0];
    expect(f.secret?.secretType).toBe("CLOUD_CREDENTIAL");
    expect(f.secret?.fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(f.secret?.redactedPreview).toBe("AKIA…MPLE");
    expect(f.secret?.verificationStatus).toBe("NOT_VERIFIED");
    expect(f.filePath).toBe("config/aws-credentials.txt");
    expect(f.startLine).toBe(2);
  });

  it("the same secret from gitleaks + trufflehog gets the SAME fingerprint (cross-tool secret identity)", () => {
    const g = parseGitleaks(FIXTURE_GITLEAKS_OUTPUT, ctxFor("gitleaks")).findings[0];
    const t = parseTrufflehog(FIXTURE_TRUFFLEHOG_OUTPUT, ctxFor("trufflehog")).findings[0];
    expect(t.secret?.fingerprint).toBe(g.secret?.fingerprint);
    expect(t.sourceFingerprint).toBe(g.sourceFingerprint);
    expect(JSON.stringify(t)).not.toContain(FIXTURE_FAKE_AWS_KEY);
  });

  it("bandit hardcoded-password snippet is redacted in evidence", () => {
    const parsed = parseBandit(FIXTURE_BANDIT_OUTPUT, ctxFor("bandit"));
    const serialized = JSON.stringify(parsed.findings);
    expect(serialized).not.toContain(FIXTURE_FAKE_PASSWORD);
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings[0].cwe).toBe("CWE-78");
  });
});

describe("Prompt 12 — archive security (§9/§106)", () => {
  it("accepts a benign zip and rejects zip-slip, symlinks, bombs and nested archives", () => {
    const good = createStoredZip([{ name: "src/app.py", data: "print('hi')" }]);
    expect(validateZipArchive(good, DEFAULT_SOURCE_BUDGET).ok).toBe(true);

    const slip = createStoredZip([{ name: "../../evil.sh", data: "x" }]);
    const slipResult = validateZipArchive(slip, DEFAULT_SOURCE_BUDGET);
    expect(slipResult.ok).toBe(false);
    expect(slipResult.errors.join(" ")).toMatch(/escapes/);

    const link = createStoredZip([{ name: "link", data: "/etc/passwd", unixMode: 0o120777 }]);
    expect(validateZipArchive(link, DEFAULT_SOURCE_BUDGET).ok).toBe(false);

    const nested = createStoredZip([{ name: "inner.zip", data: "PK" }]);
    expect(validateZipArchive(nested, DEFAULT_SOURCE_BUDGET).errors.join(" ")).toMatch(/nested/);
  });

  it("rejects decompression bombs and oversize totals from entry listings", () => {
    const bomb = validateArchiveEntries(
      [{ name: "big.bin", uncompressedSize: 500 * 1024 * 1024, compressedSize: 1024, isDirectory: false, isSymlink: false }],
      DEFAULT_SOURCE_BUDGET,
    );
    expect(bomb.ok).toBe(false);
    expect(bomb.errors.join(" ")).toMatch(/ratio|exceeds/);
  });
});

describe("Prompt 12 — git acquisition (§7/§8) + execution policy (§14/§108)", () => {
  it("clone plans disable hooks + credential helpers and carry no credentials", () => {
    const plan = buildGitClonePlan({ url: "https://github.com/example/repo.git", destination: "/srv/snapshots/abc", budget: DEFAULT_SOURCE_BUDGET });
    expect(plan.args).toContain("core.hooksPath=/dev/null");
    expect(plan.args).toContain("credential.helper=");
    expect(plan.environment.GIT_TERMINAL_PROMPT).toBe("0");
    expect(plan.args.join(" ")).not.toMatch(/token|password|oauth/i);
    expect(plan.depth).toBe(DEFAULT_SOURCE_BUDGET.maxHistoryDepth);
  });

  it("repository URLs: SSRF-blocked hosts and embedded credentials are rejected", () => {
    expect(validateRepositoryUrl("https://github.com/example/repo.git").ok).toBe(true);
    expect(validateRepositoryUrl("http://169.254.169.254/latest/meta-data").ok).toBe(false);
    expect(validateRepositoryUrl("https://user:secret@github.com/example/repo.git").ok).toBe(false);
    expect(validateRepositoryUrl("file:///etc/passwd").ok).toBe(false);
    expect(validateRepositoryUrl("https://10.0.0.5/repo.git").ok).toBe(false);
    expect(validateRepositoryUrl("https://10.0.0.5/repo.git", { allowInternal: true }).ok).toBe(true);
  });

  it("the execution policy forbids every form of source execution", () => {
    for (const action of ["BUILD_SCRIPT", "PACKAGE_LIFECYCLE_SCRIPT", "TARGET_TEST", "GIT_HOOK", "SHELL_COMMAND"] as const) {
      expect(executionPolicyViolation(DEFAULT_REPOSITORY_EXECUTION_POLICY, action)).toMatch(/never executed/);
    }
    expect(executionPolicyViolation(DEFAULT_REPOSITORY_EXECUTION_POLICY, "READ_ONLY_ANALYSIS")).toBeNull();
  });

  it("budget clamps to administrator caps", () => {
    const clamped = clampSourceBudget({ maxFiles: 10_000_000, maxRepositorySizeMb: 1 });
    expect(clamped.maxFiles).toBeLessThanOrEqual(250000);
    expect(clamped.maxRepositorySizeMb).toBe(1);
  });
});

describe("Prompt 12 — detection (§15–§17/§84/§87)", () => {
  it("detects languages, frameworks and build systems from listings + manifests", () => {
    const det = detectRepository(FIXTURE_SOURCE_FILES, FIXTURE_MANIFEST_CONTENTS);
    expect(det.primaryLanguage).toBeTruthy();
    expect(det.languages.map((l) => l.language)).toEqual(expect.arrayContaining(["TypeScript", "Python", "Java", "Ruby"]));
    expect(det.buildSystems).toEqual(expect.arrayContaining(["npm", "maven", "pip", "bundler"]));
    expect(det.frameworks).toContain("Express");
  });

  it("classifies manifests, vendored, generated and test files", () => {
    expect(classifyRepositoryFile("package-lock.json")).toBe("DEPENDENCY_MANIFEST");
    expect(classifyRepositoryFile("node_modules/lodash/index.js")).toBe("VENDORED");
    expect(classifyRepositoryFile("src/app.min.js")).toBe("GENERATED");
    expect(classifyRepositoryFile("src/db.test.ts")).toBe("TEST");
    expect(classifyRepositoryFile("src/db.ts")).toBe("SOURCE");
    expect(isManifestPath("pom.xml")).toBe(true);
  });
});

describe("Prompt 12 — components, PURL, SBOM (§45–§48/§56)", () => {
  it("parses lockfiles first across ecosystems and builds PURLs", () => {
    const components = parseManifests(FIXTURE_MANIFEST_CONTENTS);
    const byPurl = new Map(components.map((c) => [c.purl, c]));
    expect(byPurl.has("pkg:npm/lodash@4.17.20")).toBe(true);
    expect(byPurl.has("pkg:npm/express@4.17.1")).toBe(true);
    expect(byPurl.has("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")).toBe(true);
    expect(byPurl.get("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")?.name).toBe("org.apache.logging.log4j:log4j-core");
    expect(byPurl.has("pkg:pypi/flask@1.1.2")).toBe(true);
    expect(byPurl.has("pkg:gem/rake@13.0.1")).toBe(true);
    expect(buildPurl("npm", "@angular/core", "17.0.0")).toBe("pkg:npm/%40angular/core@17.0.0");
    expect(buildPurl("pypi", "Django", "4.2")).toBe("pkg:pypi/django@4.2");
    expect(dedupeComponents(components)).toHaveLength(components.length);
  });

  it("generates CycloneDX + SPDX SBOMs with checksums", () => {
    const components = parseManifests(FIXTURE_MANIFEST_CONTENTS);
    const meta = { snapshotHash: "abc123", repositoryName: "fixture-repo", timestamp: "2026-10-07T00:00:00.000Z" };
    const cdx = buildCycloneDxSbom(components, meta);
    expect(cdx.sbom.format).toBe("CYCLONEDX_JSON");
    expect(cdx.sbom.componentCount).toBe(components.length);
    expect(cdx.sbom.checksum).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.parse(cdx.document).bomFormat).toBe("CycloneDX");
    const spdx = buildSpdxSbom(components, meta);
    expect(spdx.document).toContain("SPDXVersion: SPDX-2.3");
    expect(spdx.document).toContain("pkg:npm/lodash@4.17.20");
  });

  it("maps components to CPEs for governed lookup", () => {
    const log4j = parseManifests(FIXTURE_MANIFEST_CONTENTS).find((c) => c.name.includes("log4j"));
    expect(componentToCpe(log4j!)).toBe("cpe:2.3:a:org.apache.logging.log4j:log4j-core:2.14.1");
  });
});

describe("Prompt 12 — governed rule policies (§22/§30/§101)", () => {
  it("semgrep selection comes only from the catalog; arbitrary rules are rejected", () => {
    const sel = resolveSemgrepPacks({ profile: "SOURCE_BASELINE", languages: ["Python", "JavaScript"] });
    expect(sel.packs).toEqual(expect.arrayContaining(["p/security-audit", "p/python", "p/javascript"]));
    const hostile = resolveSemgrepPacks({ profile: "SOURCE_BASELINE", languages: [], requested: ["/tmp/evil-rules.yaml", "p/security-audit", "https://evil.invalid/rules"] });
    expect(hostile.packs).toEqual(["p/security-audit"]);
    expect(hostile.rejected).toHaveLength(2);
  });

  it("codeql plan uses build-mode=none suites and marks compiled-only languages BUILD_REQUIRED", () => {
    const plan = resolveCodeqlPlan(["TypeScript", "Python"]);
    expect(plan.languages.map((l) => l.language)).toEqual(expect.arrayContaining(["typescript", "python"]));
    expect(plan.languages.every((l) => l.buildMode === "none")).toBe(true);
    const cpp = resolveCodeqlPlan(["C++"]);
    expect(cpp.buildRequired).toContain("cpp");
    expect(cpp.languages).toHaveLength(0);
  });
});

describe("Prompt 12 — SAST parsers (§21–§33)", () => {
  it("semgrep: CWE/OWASP from tool metadata, dataflow preserved, locations normalized", () => {
    const parsed = parseSemgrep(FIXTURE_SEMGREP_OUTPUT, ctxFor("semgrep"));
    expect(parsed.findings).toHaveLength(2);
    const sqli = parsed.findings.find((f) => f.filePath === "src/db.ts")!;
    expect(sqli.cwe).toBe("CWE-89");
    expect(sqli.codeFlow?.length).toBe(2);
    expect(sqli.startLine).toBe(12);
  });

  it("codeql SARIF import: same CWE/file/line as semgrep — and hostile URIs are dropped", () => {
    const parsed = importSarif(FIXTURE_CODEQL_SARIF, ctxFor("codeql"));
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].cwe).toBe("CWE-89");
    expect(parsed.findings[0].filePath).toBe("src/db.ts");
    const hostile = importSarif(JSON.stringify({
      runs: [{ tool: { driver: { name: "X", rules: [] } }, results: [{ ruleId: "r", message: { text: "m" }, locations: [{ physicalLocation: { artifactLocation: { uri: "../../etc/passwd" }, region: { startLine: 1 } } }] }] }],
    }), ctxFor("codeql"));
    expect(hostile.findings).toHaveLength(0);
    expect(hostile.warnings.join(" ")).toMatch(/outside repository/);
  });

  it("spotbugs imports SECURITY findings only — style bugs are not vulnerabilities", () => {
    const parsed = parseSpotbugs(FIXTURE_SPOTBUGS_OUTPUT, ctxFor("spotbugs"));
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].ruleId).toBe("SQL_INJECTION_JDBC");
    expect(parsed.metrics.nonSecurityBugsSkipped).toBe(1);
  });

  it("brakeman maps Rails warnings with tool-provided CWE", () => {
    const parsed = parseBrakeman(FIXTURE_BRAKEMAN_OUTPUT, ctxFor("brakeman"));
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].cwe).toBe("CWE-89");
    expect(parsed.findings[0].severity).toBe("HIGH");
  });

  it("sonar: hotspots are REVIEW_REQUIRED, code smells are skipped (§26/§27)", () => {
    const parsed = parseSonarIssues(FIXTURE_SONAR_OUTPUT, ctxFor("sonarqube"));
    expect(parsed.findings).toHaveLength(2);
    const hotspot = parsed.findings.find((f) => f.reviewStatus === "REVIEW_REQUIRED")!;
    expect(hotspot).toBeTruthy();
    expect(parsed.metrics.nonSecurityIssuesSkipped).toBe(1);
  });
});

describe("Prompt 12 — correlation & baselines (§64–§68/§79/§103)", () => {
  it("fingerprints are line-movement stable: line 50 → 60 is the same finding", () => {
    const a = sourceFingerprint({ repositoryKey: "r", filePath: "src/db.ts", ruleId: "js/sql-injection", context: "db.query(userId)" });
    const b = sourceFingerprint({ repositoryKey: "r", filePath: "src/db.ts", ruleId: "js/sql-injection", context: "db.query(userId)" });
    expect(a).toBe(b); // no line number participates
    const changed = sourceFingerprint({ repositoryKey: "r", filePath: "src/db.ts", ruleId: "js/sql-injection", context: "db.query(other)" });
    expect(changed).not.toBe(a);
  });

  it("cross-tool SAST correlation merges semgrep+codeql (same file+CWE+line) but never on CWE alone", () => {
    const semgrep = parseSemgrep(FIXTURE_SEMGREP_OUTPUT, ctxFor("semgrep")).findings;
    const codeql = importSarif(FIXTURE_CODEQL_SARIF, ctxFor("codeql")).findings;
    const { findings, stats } = correlateSourceFindings([...semgrep, ...codeql]);
    const sqli = findings.filter((f) => f.cwe === "CWE-89" && f.filePath === "src/db.ts");
    expect(sqli).toHaveLength(1);
    expect(sqli[0].sources).toEqual(expect.arrayContaining(["semgrep", "codeql"]));
    expect(stats.crossToolMerges).toBe(1);
    // Same CWE, different file → stays separate.
    const apart = correlateSourceFindings([
      { ...codeql[0], filePath: "src/other.ts", sourceFingerprint: "fp-other" },
      codeql[0],
    ]);
    expect(apart.findings).toHaveLength(2);
  });

  it("secret findings from two tools merge into one canonical finding", () => {
    const g = parseGitleaks(FIXTURE_GITLEAKS_OUTPUT, ctxFor("gitleaks")).findings;
    const t = parseTrufflehog(FIXTURE_TRUFFLEHOG_OUTPUT, ctxFor("trufflehog")).findings;
    const { findings } = correlateSourceFindings([...g, ...t]);
    expect(findings).toHaveLength(1);
    expect(findings[0].sources).toEqual(expect.arrayContaining(["gitleaks", "trufflehog"]));
  });

  it("baseline classification: NEW / EXISTING / RESOLVED", () => {
    const { statuses, resolved } = classifyBaseline(
      [{ sourceFingerprint: "a" }, { sourceFingerprint: "b" }],
      ["b", "c"],
    );
    expect(statuses.get("a")).toBe("NEW");
    expect(statuses.get("b")).toBe("EXISTING");
    expect(resolved).toEqual(["c"]);
  });
});

describe("Prompt 12 — SCA (§49–§58/§102)", () => {
  it("dependency-check + grype merge by component+CVE; fixed versions from trusted data", () => {
    const dc = parseDependencyCheck(FIXTURE_DEPCHECK_OUTPUT, ctxFor("owasp-dependency-check")).findings;
    const grype = parseGrype(FIXTURE_GRYPE_OUTPUT, ctxFor("grype")).findings;
    const merged = mergeDependencyObservations([...dc, ...grype]);
    const log4j = merged.filter((f) => f.cve === "CVE-2021-44228");
    expect(log4j).toHaveLength(1);
    expect(log4j[0].sources).toEqual(expect.arrayContaining(["owasp-dependency-check", "grype"]));
    expect(log4j[0].fixedVersion).toBe("2.15.0");
    expect(merged.filter((f) => f.cve === "CVE-2021-23337")).toHaveLength(1);
  });

  it("intel matching: POTENTIAL_EXPOSURE from the governed dataset; EMPTY dataset ⇒ zero matches", () => {
    const components = parseManifests(FIXTURE_MANIFEST_CONTENTS);
    const drafts = matchComponentsAgainstIntel(components, fixtureIntelligenceDataset());
    expect(drafts).toHaveLength(1);
    expect(drafts[0].cve).toBe("CVE-2021-44228");
    expect(drafts[0].reachability).toBe("POTENTIAL_EXPOSURE");
    expect(drafts[0].evidence).toMatch(/EPSS/);
    const empty = matchComponentsAgainstIntel(components, new InMemoryIntelligenceDataset());
    expect(empty).toHaveLength(0);
  });

  it("enrichment attaches EPSS/KEV only when the dataset holds the CVE", () => {
    const grype = parseGrype(FIXTURE_GRYPE_OUTPUT, ctxFor("grype")).findings;
    const enriched = enrichDependencyFindings(grype, fixtureIntelligenceDataset());
    expect(enriched.find((f) => f.cve === "CVE-2021-44228")?.evidence).toMatch(/KEV/);
    const unenriched = enrichDependencyFindings(grype, new InMemoryIntelligenceDataset());
    expect(unenriched.find((f) => f.cve === "CVE-2021-44228")?.evidence ?? "").not.toMatch(/KEV/);
  });
});

describe("Prompt 12 — quality gate (§81/§82/§104)", () => {
  it("fails on criticals and secrets, warns on new highs, passes clean scans", () => {
    const failing = evaluateQualityGate(
      summarizeForQualityGate([{ severity: "CRITICAL" }, { severity: "HIGH", secret: { any: true } }]),
      DEFAULT_QUALITY_GATE_POLICY,
    );
    expect(failing.status).toBe("FAILED");
    expect(failing.failedRules).toEqual(expect.arrayContaining(["no-critical", "no-secrets"]));
    const warning = evaluateQualityGate(
      summarizeForQualityGate([{ severity: "HIGH", baselineStatus: "NEW" }]),
      DEFAULT_QUALITY_GATE_POLICY,
    );
    expect(warning.status).toBe("WARNING");
    const passing = evaluateQualityGate(summarizeForQualityGate([{ severity: "LOW" }]), DEFAULT_QUALITY_GATE_POLICY);
    expect(passing.status).toBe("PASSED");
  });
});

describe("Prompt 12 — adapters (§13/§22/§29/§37/§108)", () => {
  it("adapter plans are argument arrays with NO_NETWORK and no source execution — hostile package.json scripts are never invoked", async () => {
    const adapters = createCodeAdapters();
    const target = { type: "SOURCE_REPOSITORY" as const, value: "/srv/snapshots/fixture", host: "fixture" };
    for (const adapter of adapters) {
      const plan = await adapter.buildExecutionPlan(target, { sourcePath: "/srv/snapshots/fixture", repositoryId: "repo-1", languages: ["Python", "TypeScript"] });
      expect(plan.networkPolicy).toBe("NO_NETWORK");
      const all = [plan.executable ?? "", ...plan.arguments].join(" ");
      expect(all).not.toMatch(/npm|pip install|preinstall|postinstall|make |gradle|mvn /);
      expect(all).not.toContain("evil.invalid");
    }
  });

  it("semgrep plan uses governed packs only", async () => {
    const [semgrep] = createCodeAdapters();
    const plan = await semgrep.buildExecutionPlan(
      { type: "SOURCE_REPOSITORY", value: "/srv/snapshots/fixture", host: "fixture" },
      { sourcePath: "/srv/snapshots/fixture", languages: ["Python"], rulePacks: ["p/security-audit", "p/python"] },
    );
    expect(plan.arguments).toContain("p/security-audit");
    expect(plan.arguments).not.toContain("--config \"/tmp/evil\"");
  });

  it("trufflehog always disables verification and rejects enabling it", async () => {
    const trufflehog = createCodeAdapters().find((a) => a.metadata.slug === "trufflehog")!;
    const plan = await trufflehog.buildExecutionPlan(
      { type: "SOURCE_REPOSITORY", value: "/srv/snapshots/fixture", host: "fixture" },
      { sourcePath: "/srv/snapshots/fixture" },
    );
    expect(plan.arguments).toContain("--no-verification");
    await expect(trufflehog.validateConfiguration({ externalVerification: true })).rejects.toThrow(/disabled by platform policy/);
  });

  it("codeql refuses compiled-only languages as BUILD_REQUIRED instead of building", async () => {
    const codeql = createCodeAdapters().find((a) => a.metadata.slug === "codeql")!;
    await expect(codeql.buildExecutionPlan(
      { type: "SOURCE_REPOSITORY", value: "/srv/snapshots/fixture", host: "fixture" },
      { sourcePath: "/srv/snapshots/fixture", languages: ["C++"] },
    )).rejects.toThrow(/BUILD_REQUIRED/);
  });

  it("health is honest: no binaries on this host ⇒ UNAVAILABLE", async () => {
    const [semgrep] = createCodeAdapters();
    const health = await semgrep.healthCheck();
    expect(["UNAVAILABLE", "HEALTHY"]).toContain(health.status); // depends on host PATH; never fabricated
    if (health.status === "UNAVAILABLE") expect(health.detail).toMatch(/not found on PATH/);
  });
});

describe("Prompt 12 — source retests (§77)", () => {
  it("plans per finding kind and judges honestly", () => {
    const secretPlan = planSourceRetest({ sourceFingerprint: "fp1", secret: { any: true } });
    expect(secretPlan.profile).toBe("SECRETS_ONLY");
    const depPlan = planSourceRetest({ sourceFingerprint: "fp2", componentPurl: "pkg:npm/lodash@4.17.20", fixedVersion: "4.17.21" });
    expect(depPlan.kind).toBe("DEPENDENCY");
    expect(judgeSourceRetest(depPlan, { fingerprints: [], components: [{ purl: "pkg:npm/lodash@4.17.21", version: "4.17.21" }], scanCompleted: true }).outcome).toBe("RESOLVED");
    expect(judgeSourceRetest(depPlan, { fingerprints: ["fp2"], components: [{ purl: "pkg:npm/lodash@4.17.20", version: "4.17.20" }], scanCompleted: true }).outcome).toBe("STILL_PRESENT");
    expect(judgeSourceRetest(depPlan, { fingerprints: [], components: [], scanCompleted: false }).outcome).toBe("INCONCLUSIVE");
    expect(compareVersions("2.15.0", "2.14.1")).toBe(1);
    expect(compareVersions("4.17.20", "4.17.21")).toBe(-1);
  });
});
