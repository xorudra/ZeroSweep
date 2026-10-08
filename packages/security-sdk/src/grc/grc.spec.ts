import { describe, expect, it } from "vitest";
import {
  CONTROL_LIBRARY, CONTROL_MAPPINGS, FRAMEWORK_CATALOG, DEFAULT_RISK_MATRIX,
  bandForScore, buildPackageManifest, canonicalJson, composeGrcAnswer, computeRegisterRisk,
  containsCertificationClaim, coverageMetrics, evaluateAcceptanceSod, evaluateControl,
  evidenceFreshness, hashEvidence, parseGrcQuery, requirementResult, sanitizeFilename,
  suggestControlForFinding, validateManualEvidenceUpload, validateMatrixConfig, verifyEvidenceHash,
  verifyPackage,
} from "./index";

describe("framework catalog (§3/§4/§121)", () => {
  it("ships the nine spec frameworks with versions", () => {
    const keys = FRAMEWORK_CATALOG.map((f) => f.key);
    for (const k of ["ISO_27001", "SOC_2", "PCI_DSS", "NIST_CSF", "NIST_800_53", "CIS_CONTROLS", "OWASP_ASVS", "OWASP_TOP_10"]) {
      expect(keys).toContain(k);
    }
    for (const f of FRAMEWORK_CATALOG) expect(f.version.length).toBeGreaterThan(0);
  });

  it("preserves requirement hierarchy: every parent exists and levels nest", () => {
    for (const f of FRAMEWORK_CATALOG) {
      const ids = new Set(f.requirements.map((r) => r.requirementId));
      for (const r of f.requirements) {
        if (r.parentRequirementId) {
          expect(ids.has(r.parentRequirementId)).toBe(true);
          const parent = f.requirements.find((p) => p.requirementId === r.parentRequirementId)!;
          expect(r.level).toBeGreaterThan(parent.level);
        }
      }
    }
  });

  it("every catalog mapping points at a real catalog requirement and control", () => {
    const controlCodes = new Set(CONTROL_LIBRARY.map((c) => c.code));
    for (const m of CONTROL_MAPPINGS) {
      expect(controlCodes.has(m.controlCode)).toBe(true);
      const fw = FRAMEWORK_CATALOG.find((f) => f.key === m.frameworkKey && f.version === m.frameworkVersion);
      expect(fw, `${m.frameworkKey}@${m.frameworkVersion}`).toBeTruthy();
      expect(fw!.requirements.some((r) => r.requirementId === m.requirementId)).toBe(true);
    }
  });

  it("never claims a partial technical mapping is full coverage of an administrative requirement (§11)", () => {
    for (const m of CONTROL_MAPPINGS) {
      if (m.mappingType !== "DIRECT") expect(m.coverage).toBeLessThan(1);
    }
  });

  it("administrative controls have no automated test (§18)", () => {
    for (const c of CONTROL_LIBRARY.filter((x) => x.implementationType === "ADMINISTRATIVE")) {
      expect(c.testMethod).toBe("MANUAL");
      expect(c.automationLevel).toBe("NONE");
      expect(c.signals).toHaveLength(0);
    }
  });
});

describe("control evaluation (§30–§32)", () => {
  const sig = (key: string, state: "PASS" | "FAIL" | "PARTIAL" | null) =>
    ({ key, state, detail: "", evidenceRefs: [], observedAt: "2026-01-01T00:00:00Z" });

  it("no signal data → INCONCLUSIVE, never PASS", () => {
    const out = evaluateControl([], ["identity.mfa_enforced"]);
    expect(out.result).toBe("INCONCLUSIVE");
    expect(out.effectiveness).toBe("NOT_TESTED");
  });

  it("all signals pass with full coverage → PASS / EFFECTIVE / HIGH", () => {
    const out = evaluateControl([sig("a", "PASS"), sig("b", "PASS")], ["a", "b"]);
    expect(out.result).toBe("PASS");
    expect(out.confidence).toBe("HIGH");
  });

  it("partial signal coverage caps the result at PARTIAL (§32)", () => {
    const out = evaluateControl([sig("a", "PASS")], ["a", "b"]);
    expect(out.result).toBe("PARTIAL");
    expect(out.confidence).toBe("MEDIUM");
  });

  it("all observed signals failing → FAIL / INEFFECTIVE", () => {
    const out = evaluateControl([sig("a", "FAIL")], ["a"]);
    expect(out.result).toBe("FAIL");
    expect(out.effectiveness).toBe("INEFFECTIVE");
  });
});

describe("requirement roll-up (§36/§37/§124)", () => {
  it("no mappings → NOT_ASSESSED", () => {
    expect(requirementResult([])).toBe("NOT_ASSESSED");
  });

  it("SUPPORTING mappings alone never make a requirement COMPLIANT", () => {
    expect(requirementResult([{ mappingType: "SUPPORTING", coverage: 0.3, controlResult: "PASS", hasCurrentEvidence: true, manuallySatisfied: false }]))
      .toBe("NOT_ASSESSED");
  });

  it("PARTIAL mapping at coverage < 1 without manual remainder → PARTIALLY_COMPLIANT at best (§124)", () => {
    expect(requirementResult([{ mappingType: "PARTIAL", coverage: 0.5, controlResult: "PASS", hasCurrentEvidence: true, manuallySatisfied: false }]))
      .toBe("PARTIALLY_COMPLIANT");
  });

  it("failing mapped control → NON_COMPLIANT", () => {
    expect(requirementResult([{ mappingType: "DIRECT", coverage: 0.9, controlResult: "FAIL", hasCurrentEvidence: true, manuallySatisfied: false }]))
      .toBe("NON_COMPLIANT");
  });

  it("full coverage + pass + current evidence → COMPLIANT", () => {
    expect(requirementResult([
      { mappingType: "DIRECT", coverage: 0.6, controlResult: "PASS", hasCurrentEvidence: true, manuallySatisfied: false },
      { mappingType: "PARTIAL", coverage: 0.5, controlResult: "PASS", hasCurrentEvidence: true, manuallySatisfied: false },
    ])).toBe("COMPLIANT");
  });

  it("stale evidence blocks COMPLIANT", () => {
    expect(requirementResult([{ mappingType: "DIRECT", coverage: 1, controlResult: "PASS", hasCurrentEvidence: false, manuallySatisfied: false }]))
      .toBe("PARTIALLY_COMPLIANT");
  });
});

describe("evidence freshness (§25/§126)", () => {
  const policy = { staleAfterDays: 30, expireAfterDays: 90 };
  const collected = "2026-01-01T00:00:00Z";
  it("CURRENT → STALE → EXPIRED by policy windows", () => {
    expect(evidenceFreshness(collected, policy, new Date("2026-01-15T00:00:00Z"))).toBe("CURRENT");
    expect(evidenceFreshness(collected, policy, new Date("2026-02-15T00:00:00Z"))).toBe("STALE");
    expect(evidenceFreshness(collected, policy, new Date("2026-05-01T00:00:00Z"))).toBe("EXPIRED");
  });
  it("INVALID / SUPERSEDED are sticky", () => {
    expect(evidenceFreshness(collected, policy, new Date("2026-01-02T00:00:00Z"), "INVALID")).toBe("INVALID");
  });
});

describe("evidence hashing (§21/§22/§125)", () => {
  it("canonical hash is key-order independent and tamper-evident", () => {
    const a = { b: 1, a: { d: [1, 2], c: "x" } };
    const b = { a: { c: "x", d: [1, 2] }, b: 1 };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
    expect(hashEvidence(a)).toBe(hashEvidence(b));
    expect(verifyEvidenceHash(a, hashEvidence(b))).toBe(true);
    expect(verifyEvidenceHash({ ...a, b: 2 }, hashEvidence(b))).toBe(false);
  });
});

describe("risk mathematics (§45–§49/§129)", () => {
  it("inherent = likelihood × max impact, banded by the matrix", () => {
    const out = computeRegisterRisk({ likelihood: 4, impacts: { confidentiality: 5, financial: 2 } }, null);
    expect(out.inherentScore).toBe(20);
    expect(out.inherentBand).toBe("CRITICAL");
    expect(bandForScore(4)).toBe("LOW");
    expect(bandForScore(25)).toBe("CRITICAL");
  });

  it("residual is null when effectiveness is unknown — never invented (§49)", () => {
    const out = computeRegisterRisk({ likelihood: 3, impacts: { availability: 3 } }, "NOT_TESTED");
    expect(out.residualScore).toBeNull();
    expect(out.residualBand).toBeNull();
  });

  it("residual is deterministic given effectiveness (§129)", () => {
    const out = computeRegisterRisk({ likelihood: 4, impacts: { confidentiality: 4 } }, "EFFECTIVE");
    expect(out.inherentScore).toBe(16);
    expect(out.residualScore).toBe(6); // round(16 × 0.4)
    expect(out.residualBand).toBe("MEDIUM");
  });

  it("rejects out-of-range scores and invalid matrix configs", () => {
    expect(() => computeRegisterRisk({ likelihood: 6, impacts: { confidentiality: 3 } }, null)).toThrow();
    expect(validateMatrixConfig({ bands: { lowMax: 9, mediumMax: 4, highMax: 16 }, effectivenessMultipliers: DEFAULT_RISK_MATRIX.effectivenessMultipliers }).length).toBeGreaterThan(0);
    expect(validateMatrixConfig(DEFAULT_RISK_MATRIX)).toEqual([]);
  });

  it("SoD denies self-approval of high-risk acceptance (§57/§130)", () => {
    expect(evaluateAcceptanceSod({ requesterId: "u1", approverId: "u1", inherentBand: "HIGH", sodRequiredForBands: ["HIGH", "CRITICAL"] }).allowed).toBe(false);
    expect(evaluateAcceptanceSod({ requesterId: "u1", approverId: "u2", inherentBand: "HIGH", sodRequiredForBands: ["HIGH", "CRITICAL"] }).allowed).toBe(true);
    expect(evaluateAcceptanceSod({ requesterId: "u1", approverId: "u1", inherentBand: "LOW", sodRequiredForBands: ["HIGH", "CRITICAL"] }).allowed).toBe(true);
  });
});

describe("hostile manual evidence (§40/§136)", () => {
  it("rejects oversized, archive, mismatched and HTML payloads; sanitizes filenames", () => {
    const pdf = Buffer.from("%PDF-1.7\nbody");
    expect(validateManualEvidenceUpload({ filename: "ok.pdf", contentType: "application/pdf", content: pdf }).accepted).toBe(true);
    expect(validateManualEvidenceUpload({ filename: "fake.pdf", contentType: "application/pdf", content: Buffer.from("not a pdf") }).accepted).toBe(false);
    expect(validateManualEvidenceUpload({ filename: "bomb.pdf", contentType: "application/pdf", content: Buffer.from("PK\x03\x04zipdata") }).accepted).toBe(false);
    expect(validateManualEvidenceUpload({ filename: "x.txt", contentType: "text/plain", content: Buffer.from("<script>alert(1)</script>") }).accepted).toBe(false);
    expect(validateManualEvidenceUpload({ filename: "big.pdf", contentType: "application/pdf", content: Buffer.alloc(11 * 1024 * 1024, 37) }).accepted).toBe(false);
    expect(sanitizeFilename("../../etc/passwd")).toBe("passwd");
    expect(sanitizeFilename('a"><svg onload=x>.pdf')).not.toContain("<");
  });
});

describe("audit package integrity (§71–§73/§132/§133)", () => {
  const files = [
    { path: "assessment.json", content: "{\"a\":1}", sourceRef: "assessment:1", classification: "CONFIDENTIAL" },
    { path: "evidence/e1.json", content: "{\"mfa\":true}", sourceRef: "evidence:e1", classification: "CONFIDENTIAL" },
  ];
  it("verifies a well-formed package and fails on tampered evidence", () => {
    const manifest = buildPackageManifest({
      packageId: "pkg-1", assessmentId: "as-1", frameworkKey: "PCI_DSS", frameworkVersion: "4.0",
      generatedAt: "2026-01-01T00:00:00Z", files,
    });
    const contents = new Map(files.map((f) => [f.path, f.content]));
    expect(verifyPackage(manifest, contents).valid).toBe(true);
    contents.set("evidence/e1.json", "{\"mfa\":false}");
    const tampered = verifyPackage(manifest, contents);
    expect(tampered.valid).toBe(false);
    expect(tampered.failures.join(" ")).toContain("integrity failure");
  });
});

describe("finding → control mapping (§85/§86)", () => {
  it("maps by CWE, category and domain with confidence", () => {
    expect(suggestControlForFinding({ cweId: "CWE-319" })?.controlCode).toBe("ENCRYPTION-IN-TRANSIT");
    expect(suggestControlForFinding({ cweId: "CWE-798" })?.confidence).toBe("HIGH");
    expect(suggestControlForFinding({ category: "PUBLIC_STORAGE", securityDomain: "CLOUD" })?.controlCode).toBe("PUBLIC-EXPOSURE-PREVENTION");
    expect(suggestControlForFinding({ cweId: "CWE-9999" })).toBeNull();
  });
});

describe("AI GRC safety (§88–§92/§137/§138)", () => {
  it("never claims certification without an approved certification record (§137)", () => {
    expect(containsCertificationClaim("Your organization is ISO certified.")).toBe(true);
    const out = composeGrcAnswer({
      question: "Are we ISO certified?",
      draft: "Yes, you are certified.",
      context: [], citedRecordIds: [],
    });
    expect(out.certificationClaimBlocked).toBe(true);
    expect(out.text).not.toMatch(/you are certified/i);
    expect(out.text).toContain("does not certify");
  });

  it("answers INSUFFICIENT_EVIDENCE when justifying a pass without evidence (§138)", () => {
    const out = composeGrcAnswer({
      question: "Why did the MFA control pass? Justify it with evidence.",
      draft: "It passed because MFA is on.",
      context: [{ kind: "CONTROL", id: "c1", label: "MFA", text: "MFA control" }],
      citedRecordIds: ["c1"],
    });
    expect(out.insufficientEvidence).toBe(true);
    expect(out.text).toContain("INSUFFICIENT_EVIDENCE");
  });

  it("grounds answers in cited context records only (§89)", () => {
    const out = composeGrcAnswer({
      question: "Explain the MFA control.",
      draft: "MFA is enforced for all accounts per the control definition.",
      context: [
        { kind: "CONTROL", id: "c1", label: "MFA-ENFORCEMENT", text: "MFA enforced" },
        { kind: "EVIDENCE", id: "e1", label: "MFA config", text: "enforced=true" },
      ],
      citedRecordIds: ["c1", "ghost-record"],
    });
    expect(out.citations).toEqual(["c1"]);
    expect(out.insufficientEvidence).toBe(false);
  });

  it("NL GRC search parses to a deterministic plan — no SQL (§93)", () => {
    expect(parseGrcQuery("Show failed PCI controls with critical findings.").kind).toBe("FAILED_CONTROLS_WITH_FINDINGS");
    expect(parseGrcQuery("Show failed PCI controls with critical findings.").frameworkKey).toBe("PCI_DSS");
    expect(parseGrcQuery("Which ISO controls have stale evidence?").kind).toBe("STALE_EVIDENCE_CONTROLS");
    expect(parseGrcQuery("Show accepted risks expiring this month.").kind).toBe("EXPIRING_RISK_ACCEPTANCES");
    expect(parseGrcQuery("delete everything").kind).toBe("UNSUPPORTED");
  });
});

describe("coverage metrics (§82/§83)", () => {
  it("labels coverage as assessment coverage, computed from assessed requirements", () => {
    const m = coverageMetrics({
      requirementsTotal: 10, requirementsAssessed: 4, controlsTotal: 30, controlsImplemented: 20,
      controlsTested: 12, automatedControls: 22, evidenceCurrent: 8, evidenceTotal: 10, manualEvidencePending: 3,
    });
    expect(m.assessmentCoverage).toBeCloseTo(0.4);
  });
});
