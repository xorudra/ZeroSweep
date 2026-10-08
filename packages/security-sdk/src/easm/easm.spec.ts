import { describe, expect, it } from "vitest";
import { normalizeDomain, normalizeIp, normalizeUrl, normalizeCertificateFingerprint } from "./normalize";
import { resolveOwnership, canPromoteCandidate } from "./ownership";
import { diffDnsSnapshots, detectWildcard, assessDanglingDns, dnsSnapshotHash } from "./dns";
import { certificateState, diffCertificate } from "./certificates";
import { resolveTechnology, resolveTechnologies } from "./technology";
import { classifyInternetExposure, deriveRiskSignals, sensitiveServiceClass, driftSeverity } from "./exposure";
import { compareSnapshots, applyFlappingFilter, nextLifecycleOnObservation, type EasmSnapshot } from "./drift";
import { classifyUrlPath, normalizeHistoricalUrls, parameterNames } from "./urls";

describe("§131 domain normalization", () => {
  it("canonicalizes case and trailing dot", () => {
    const n = normalizeDomain("WWW.Example.COM.");
    expect(n?.ascii).toBe("www.example.com");
    expect(n?.isIdn).toBe(false);
  });
  it("converts IDN to punycode and preserves unicode", () => {
    const n = normalizeDomain("bücher.example");
    expect(n?.ascii).toBe("xn--bcher-kva.example");
    expect(n?.unicode).toBe("bücher.example");
    expect(n?.isIdn).toBe(true);
    // Same asset spelled in punycode collapses to the same identity.
    expect(normalizeDomain("xn--bcher-kva.example")?.ascii).toBe(n?.ascii);
  });
  it("flags mixed-script homograph labels as suspicious (signal, not verdict)", () => {
    // "pаypal" with a Cyrillic а.
    const n = normalizeDomain("p\u0430ypal.example");
    expect(n?.suspiciousIdn).toBe(true);
    // A plain single-script IDN is not flagged.
    expect(normalizeDomain("bücher.example")?.suspiciousIdn).toBe(false);
  });
  it("rejects garbage", () => {
    expect(normalizeDomain("not a domain")).toBeNull();
    expect(normalizeDomain("a/b.example")).toBeNull();
  });
});

describe("§23 IP normalization", () => {
  it("compresses IPv6 deterministically", () => {
    expect(normalizeIp("2001:0db8:0000:0000:0000:ff00:0042:8329")).toBe("2001:db8::ff00:42:8329");
    expect(normalizeIp("2001:DB8::FF00:42:8329")).toBe("2001:db8::ff00:42:8329");
  });
  it("strips IPv4 leading zeros", () => {
    expect(normalizeIp("192.168.001.010")).toBe("192.168.1.10");
    expect(normalizeIp("example.com")).toBeNull();
  });
});

describe("§24 URL normalization", () => {
  it("drops default ports, keeps distinct paths distinct", () => {
    expect(normalizeUrl("https://Example.com:443/a")?.identity).toBe("https://example.com/a");
    expect(normalizeUrl("https://example.com/a")?.identity).not.toBe(normalizeUrl("https://example.com/b")?.identity);
    expect(normalizeUrl("https://example.com:8443/a")?.port).toBe(8443);
  });
});

describe("§132 wildcard DNS", () => {
  it("recognizes wildcard and prevents candidate explosion semantics", () => {
    const w = detectWildcard([
      { label: "aaa", addresses: ["203.0.113.10"] },
      { label: "zzz-random", addresses: ["203.0.113.10"] },
      { label: "q42", addresses: ["203.0.113.10"] },
    ]);
    expect(w.wildcard).toBe(true);
    const nw = detectWildcard([
      { label: "a", addresses: ["203.0.113.10"] },
      { label: "b", addresses: ["203.0.113.11"] },
    ]);
    expect(nw.wildcard).toBe(false);
  });
});

describe("§28 DNS diff", () => {
  it("emits add/remove and CNAME target change", () => {
    const before = [
      { type: "A" as const, value: "203.0.113.10" },
      { type: "CNAME" as const, value: "old.example.net" },
    ];
    const after = [
      { type: "A" as const, value: "203.0.113.10" },
      { type: "A" as const, value: "203.0.113.11" },
      { type: "CNAME" as const, value: "new.example.net" },
    ];
    const events = diffDnsSnapshots(before, after);
    expect(events).toContainEqual(expect.objectContaining({ kind: "DNS_RECORD_ADDED", recordType: "A", after: "203.0.113.11" }));
    expect(events).toContainEqual(expect.objectContaining({ kind: "DNS_TARGET_CHANGED", recordType: "CNAME", before: "old.example.net", after: "new.example.net" }));
    expect(dnsSnapshotHash("example.com", before)).not.toBe(dnsSnapshotHash("example.com", after));
    expect(dnsSnapshotHash("example.com", [...before].reverse())).toBe(dnsSnapshotHash("example.com", before));
  });
});

describe("§141 dangling DNS", () => {
  it("candidate only when claimable target does not resolve", () => {
    const records = [{ type: "CNAME" as const, value: "gone.github.io" }];
    expect(assessDanglingDns({ records, targetResolution: "NXDOMAIN" }).isCandidate).toBe(true);
    expect(assessDanglingDns({ records, targetResolution: "RESOLVES" }).isCandidate).toBe(false);
    expect(assessDanglingDns({ records, targetResolution: "UNKNOWN" }).isCandidate).toBe(false);
    expect(assessDanglingDns({ records: [{ type: "CNAME" as const, value: "real.example.net" }], targetResolution: "NXDOMAIN" }).isCandidate).toBe(false);
  });
});

describe("§38/§39 certificates", () => {
  const now = new Date("2026-10-08T00:00:00Z");
  it("computes health states with thresholds", () => {
    expect(certificateState(new Date("2027-10-08"), now)).toBe("HEALTHY");
    expect(certificateState(new Date("2026-10-28"), now)).toBe("EXPIRING");
    expect(certificateState(new Date("2026-10-12"), now)).toBe("URGENT");
    expect(certificateState(new Date("2026-10-01"), now)).toBe("EXPIRED");
  });
  it("emits added/replaced/expired change events", () => {
    expect(diffCertificate({ host: "h", before: null, after: { fingerprint: "a", state: "HEALTHY" } })[0]?.kind).toBe("CERTIFICATE_ADDED");
    expect(diffCertificate({ host: "h", before: { fingerprint: "a", state: "HEALTHY" }, after: { fingerprint: "b", state: "HEALTHY" } })[0]?.kind).toBe("CERTIFICATE_REPLACED");
    const expired = diffCertificate({ host: "h", before: { fingerprint: "a", state: "HEALTHY" }, after: { fingerprint: "a", state: "EXPIRED" } });
    expect(expired.map((e) => e.kind)).toContain("CERTIFICATE_EXPIRED");
  });
  it("normalizes fingerprints", () => {
    expect(normalizeCertificateFingerprint("AA:BB:" + "ab".repeat(30))).toHaveLength(64);
    expect(normalizeCertificateFingerprint("zz")).toBeNull();
  });
});

describe("§65–§71 ownership resolution & promotion", () => {
  it("VERIFIED requires a completed verification workflow", () => {
    const r = resolveOwnership({ evidence: [{ kind: "ROOT_RELATIONSHIP", reference: "root-1" }, { kind: "CERTIFICATE_SAN", reference: "cert-1" }] });
    expect(r.status).toBe("LIKELY");
    expect(r.confidence).toBe("HIGH");
    const v = resolveOwnership({ evidence: [{ kind: "DNS_TXT_VERIFIED", reference: "ver-1" }] });
    expect(v.status).toBe("VERIFIED");
    expect(v.confidence).toBe("VERIFIED");
  });
  it("third-party declaration wins and blocks promotion", () => {
    const r = resolveOwnership({ evidence: [{ kind: "THIRD_PARTY_DECLARATION", reference: "decl-1" }] });
    expect(r.status).toBe("THIRD_PARTY");
    expect(canPromoteCandidate({ ownershipStatus: r.status, ownershipConfidence: r.confidence, policyAllowsPromotion: true }).allowed).toBe(false);
  });
  it("promotion never implies active authorization inputs change", () => {
    expect(canPromoteCandidate({ ownershipStatus: "VERIFIED", ownershipConfidence: "VERIFIED", policyAllowsPromotion: true }).allowed).toBe(true);
    expect(canPromoteCandidate({ ownershipStatus: "LIKELY", ownershipConfidence: "MEDIUM", policyAllowsPromotion: true }).allowed).toBe(false);
    expect(canPromoteCandidate({ ownershipStatus: "VERIFIED", ownershipConfidence: "VERIFIED", policyAllowsPromotion: false }).allowed).toBe(false);
  });
});

describe("§145/§146 technology confidence & version safety", () => {
  it("independent sources raise confidence; repetition does not", () => {
    const one = resolveTechnology([{ technology: "nginx", source: "httpx" }]);
    expect(one?.confidence).toBe("LOW");
    const two = resolveTechnology([
      { technology: "nginx", source: "httpx" },
      { technology: "nginx", source: "whatweb" },
      { technology: "nginx", source: "httpx" },
    ]);
    expect(two?.confidence).toBe("MEDIUM");
    expect(two?.sources).toHaveLength(2);
  });
  it("family-only evidence leaves version unknown", () => {
    const r = resolveTechnology([{ technology: "WordPress", source: "wappalyzer", familyOnly: true }]);
    expect(r?.version).toBeNull();
    const v = resolveTechnology([{ technology: "nginx", source: "banner", version: "1.25.1" }]);
    expect(v?.version).toBe("1.25.1");
    const conflict = resolveTechnologies([
      { technology: "nginx", source: "a", version: "1.25" },
      { technology: "nginx", source: "b", version: "1.24" },
    ]);
    expect(conflict[0]?.version).toBeNull();
  });
});

describe("§74/§78 exposure & signals", () => {
  it("classifies from evidence only", () => {
    expect(classifyInternetExposure({}).state).toBe("UNKNOWN");
    expect(classifyInternetExposure({ checkedAndAbsent: true }).state).toBe("NOT_OBSERVED");
    expect(classifyInternetExposure({ dnsPubliclyResolvable: true }).state).toBe("INTERNET_EXPOSED");
  });
  it("gates public signals on exposure", () => {
    expect(deriveRiskSignals({ exposureState: "UNKNOWN", ownershipStatus: "UNKNOWN", isNew: true })).toEqual([]);
    const signals = deriveRiskSignals({
      exposureState: "INTERNET_EXPOSED", ownershipStatus: "UNKNOWN", isNew: true,
      sensitiveServiceClasses: ["DATABASE"], certificateState: "EXPIRING", hasKevFinding: true,
    });
    expect(signals).toEqual(expect.arrayContaining(["NEW_PUBLIC_ASSET", "UNKNOWN_PUBLIC_ASSET", "PUBLIC_SENSITIVE_SERVICE", "EXPIRING_PUBLIC_CERTIFICATE", "PUBLIC_KEV"]));
  });
  it("classifies sensitive services without any authentication semantics", () => {
    expect(sensitiveServiceClass({ port: 5432 })).toBe("DATABASE");
    expect(sensitiveServiceClass({ port: 3389 })).toBe("REMOTE_MANAGEMENT");
    expect(sensitiveServiceClass({ port: 443 })).toBeNull();
  });
});

describe("§80–§93 drift, flapping, disappearance", () => {
  const base: EasmSnapshot = {
    capturedAt: "2026-10-01T00:00:00Z",
    assets: [{ identity: "app.example.com", services: [{ port: 443, transport: "tcp", service: "https" }], ips: ["203.0.113.10"], httpStatus: 200, httpTitle: "App", certificateFingerprint: "aa", technologies: ["nginx"], exposureState: "INTERNET_EXPOSED", ownershipStatus: "VERIFIED" }],
  };
  it("§142: new sensitive service ⇒ SERVICE_ADDED + CRITICAL severity", () => {
    const next: EasmSnapshot = {
      capturedAt: "2026-10-08T00:00:00Z",
      assets: [{ ...base.assets[0]!, services: [...base.assets[0]!.services, { port: 5432, transport: "tcp", service: "postgresql" }] }],
    };
    const drift = compareSnapshots(base, next, sensitiveServiceClass);
    const svc = drift.find((d) => d.type === "SERVICE_ADDED");
    expect(svc).toBeDefined();
    expect(svc?.severity).toBe("CRITICAL");
    expect(svc?.sensitiveServiceClass).toBe("DATABASE");
    expect(driftSeverity({ type: "HTTP_CHANGED" })).toBe("LOW");
  });
  it("§93: flapping filter requires consecutive confirmations", () => {
    const counts = new Map<string, number>();
    const c = compareSnapshots(base, { capturedAt: "x", assets: [] }, sensitiveServiceClass);
    const first = applyFlappingFilter(c, counts, 2);
    expect(first.confirmed).toHaveLength(0);
    expect(first.pending.length).toBeGreaterThan(0);
    const second = applyFlappingFilter(c, counts, 2);
    expect(second.confirmed.length).toBe(c.length);
  });
  it("§143: disappearance only after the confirmation threshold", () => {
    expect(nextLifecycleOnObservation({ currentLifecycle: "ACTIVE", observedNow: false, missCount: 0, missThreshold: 3 }).lifecycle).toBe("STALE");
    expect(nextLifecycleOnObservation({ currentLifecycle: "ACTIVE", observedNow: false, missCount: 2, missThreshold: 3 }).lifecycle).toBe("DISAPPEARED");
    expect(nextLifecycleOnObservation({ currentLifecycle: "STALE", observedNow: true, missCount: 2 }).lifecycle).toBe("ACTIVE");
  });
});

describe("§61/§64 historical URLs", () => {
  it("classifies paths and stores parameter names only", () => {
    expect(classifyUrlPath("/api/v1/users")).toBe("API");
    expect(classifyUrlPath("/login")).toBe("AUTH");
    expect(classifyUrlPath("/admin/panel")).toBe("ADMIN");
    expect(classifyUrlPath("/static/app.css")).toBe("STATIC");
    expect(parameterNames("?token=SECRET&id=3")).toEqual(["id", "token"]);
    const cands = normalizeHistoricalUrls(["https://example.com/api/x?token=SECRET", "https://example.com/api/x?other=1", "ftp://nope"]);
    expect(cands).toHaveLength(1);
    expect(JSON.stringify(cands)).not.toContain("SECRET");
  });
});
