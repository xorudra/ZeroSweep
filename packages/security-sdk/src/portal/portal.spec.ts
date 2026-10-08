import { describe, expect, it } from "vitest";
import { projectFindingForClient, generateShareToken, hashShareToken, evaluateShareLink } from "./index";

const NOW = new Date("2026-10-08T00:00:00Z");

describe("client projection (§100/§101/§143)", () => {
  const view = projectFindingForClient(
    {
      id: "f1", title: "SQL injection", description: "desc password: should-not-leak", severity: "CRITICAL",
      riskScore: 92, cve: "CVE-2024-12345", host: "app.example.com", businessImpact: "data exposure",
      remediation: "parameterize queries", lifecycleStatus: "REMEDIATED", verificationStatus: "UNVERIFIED",
      createdAt: "2026-10-01T00:00:00Z",
    },
    [
      { id: "e1", visibility: "INTERNAL", summary: "raw request with token: abcdefgh", evidenceType: "TEXT", createdAt: "2026-10-01T00:00:00Z" },
      { id: "e2", visibility: "CLIENT", summary: "sanitized screenshot reference", evidenceType: "IMAGE", createdAt: "2026-10-01T00:00:00Z" },
      { id: "e3", visibility: "RESTRICTED", summary: "restricted capture", evidenceType: "PCAP", createdAt: "2026-10-01T00:00:00Z" },
    ],
    [
      { id: "c1", visibility: "INTERNAL", authorId: "analyst-1", text: "internal note: suspect WAF bypass via cookie: session=zzz", createdAt: "2026-10-01T00:00:00Z" },
      { id: "c2", visibility: "CLIENT", authorId: "analyst-1", text: "We confirmed this on your staging host.", createdAt: "2026-10-01T00:00:00Z" },
    ],
  );

  it("shows only client-visible evidence and comments", () => {
    expect(view.evidence.map((e) => e.id)).toEqual(["e2"]);
    expect(view.comments.map((c) => c.id)).toEqual(["c2"]);
  });
  it("never carries internal strings or planted secrets into the view", () => {
    const serialized = JSON.stringify(view);
    for (const leak of ["should-not-leak", "abcdefgh", "restricted capture", "WAF bypass", "session=zzz", "raw request"]) {
      expect(serialized).not.toContain(leak);
    }
  });
  it("speaks the §7 lifecycle vocabulary (fix claimed ≠ verified)", () => {
    expect(view.status).toBe("FIX_CLAIMED");
  });
});

describe("share links (§106/§145)", () => {
  it("stores only a hash; the raw token never equals the stored value", () => {
    const token = generateShareToken();
    expect(token.length).toBeGreaterThan(20);
    expect(hashShareToken(token)).not.toBe(token);
    expect(hashShareToken(token)).toBe(hashShareToken(token));
  });
  it("denies expired, revoked and download-exhausted links", () => {
    expect(evaluateShareLink({ expiresAt: "2026-10-01T00:00:00Z", downloadCount: 0 }, NOW)).toEqual({ usable: false, reason: "EXPIRED" });
    expect(evaluateShareLink({ expiresAt: "2027-10-01T00:00:00Z", revokedAt: "2026-10-02T00:00:00Z", downloadCount: 0 }, NOW)).toEqual({ usable: false, reason: "REVOKED" });
    expect(evaluateShareLink({ expiresAt: "2027-10-01T00:00:00Z", maxDownloads: 2, downloadCount: 2 }, NOW)).toEqual({ usable: false, reason: "DOWNLOAD_LIMIT" });
    expect(evaluateShareLink({ expiresAt: "2027-10-01T00:00:00Z", maxDownloads: 2, downloadCount: 1 }, NOW)).toEqual({ usable: true });
  });
});
