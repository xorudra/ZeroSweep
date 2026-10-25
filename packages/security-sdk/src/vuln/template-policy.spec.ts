import { describe, expect, it } from "vitest";
import {
  NUCLEI_TEMPLATE_CATALOG, approvedReviewIdsForProfile, classifyTemplate,
  isTemplateAutomatable, selectTemplates,
} from "./template-policy";

/**
 * Template governance (Prompt 7 §4): automated scans may select SAFE +
 * explicitly approved REVIEW_REQUIRED templates only. INTRUSIVE and
 * DISABLED templates must be IMPOSSIBLE to select automatically — these
 * tests are the proof.
 */
describe("NucleiTemplatePolicy (§4)", () => {
  it("selects all SAFE templates by default and nothing else", () => {
    const { selected, rejected } = selectTemplates();
    expect(selected.every((t) => t.classification === "SAFE")).toBe(true);
    expect(selected.map((t) => t.id)).toContain("http-missing-security-headers");
    expect(rejected.map((r) => r.id)).toContain("cors-misconfiguration"); // REVIEW_REQUIRED, unapproved
  });

  it("includes REVIEW_REQUIRED only when explicitly approved", () => {
    const { selected } = selectTemplates({ approvedReviewIds: ["cors-misconfiguration"] });
    expect(selected.map((t) => t.id)).toContain("cors-misconfiguration");
    expect(selected.map((t) => t.id)).not.toContain("open-redirect");
  });

  it("can NEVER select INTRUSIVE or DISABLED templates — even if 'approved'", () => {
    const allIds = NUCLEI_TEMPLATE_CATALOG.map((t) => t.id);
    const { selected, rejected } = selectTemplates({ approvedReviewIds: allIds });
    const ids = selected.map((t) => t.id);
    expect(ids).not.toContain("sqli-error-based");
    expect(ids).not.toContain("xss-reflected-probe");
    expect(ids).not.toContain("ssrf-oast-probe");
    expect(ids).not.toContain("default-login-check");
    expect(ids).not.toContain("fuzzing-parameter-dos");
    expect(rejected.find((r) => r.id === "default-login-check")!.reason).toMatch(/never automatically selected/);
  });

  it("classifies unknown templates REVIEW_REQUIRED (never SAFE by default)", () => {
    expect(classifyTemplate({ id: "some-future-check" }).classification).toBe("REVIEW_REQUIRED");
    expect(classifyTemplate({ id: "rce-exploit-check" }).classification).toBe("DISABLED");
    expect(classifyTemplate({ id: "my-xss-thing" }).classification).toBe("INTRUSIVE");
    expect(isTemplateAutomatable("some-future-check")).toBe(false);
    expect(isTemplateAutomatable("some-future-check", ["some-future-check"])).toBe(true);
    expect(isTemplateAutomatable("sqli-error-based", ["sqli-error-based"])).toBe(false);
  });

  it("caps selection at maxTemplates and records the budget rejection", () => {
    const { selected, rejected } = selectTemplates({ maxTemplates: 2 });
    expect(selected).toHaveLength(2);
    expect(rejected.some((r) => /maxTemplates/.test(r.reason))).toBe(true);
  });

  it("profile approvals: only WEB_COMPREHENSIVE carries the pre-approved review set (§50)", () => {
    expect(approvedReviewIdsForProfile("WEB_BASELINE")).toEqual([]);
    expect(approvedReviewIdsForProfile("PASSIVE_RECON")).toEqual([]);
    expect(approvedReviewIdsForProfile("WEB_COMPREHENSIVE")).toEqual(
      expect.arrayContaining(["cors-misconfiguration", "open-redirect", "http-trace-method"]),
    );
  });

  it("snapshot is frozen metadata recorded for plans (§6)", () => {
    const { snapshot } = selectTemplates();
    expect(snapshot.version).toBeTruthy();
    expect(snapshot.collection).toBe("zerosweep-governed");
  });
});
