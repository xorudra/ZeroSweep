import { createHash } from "node:crypto";

/**
 * DNS intelligence (Prompt 29 §25–§34). Snapshots are immutable,
 * hashed observations; change events are derived by comparing two
 * snapshots, never asserted by a source. Dangling-DNS output is a
 * CANDIDATE with observable evidence (§29) — the platform never
 * attempts a takeover.
 */

export type DnsRecordType = "A" | "AAAA" | "CNAME" | "MX" | "NS" | "TXT";

export interface DnsRecord {
  type: DnsRecordType;
  value: string;
  ttl?: number;
}

export interface DnsSnapshotInput {
  domain: string;
  records: DnsRecord[];
  source: string;
  observedAt: Date;
}

/** Canonical snapshot hash (§26): order-independent. */
export function dnsSnapshotHash(domain: string, records: DnsRecord[]): string {
  const canonical = records
    .map((r) => `${r.type}:${r.value.trim().toLowerCase()}`)
    .sort()
    .join("\n");
  return createHash("sha256").update(`${domain.toLowerCase()}\n${canonical}`).digest("hex");
}

export type DnsChangeKind = "DNS_RECORD_ADDED" | "DNS_RECORD_REMOVED" | "DNS_TARGET_CHANGED";

export interface DnsChangeEvent {
  kind: DnsChangeKind;
  recordType: DnsRecordType;
  before: string | null;
  after: string | null;
}

/** §28: diff two snapshots of the same domain. A CNAME/A/AAAA target
 *  swap is TARGET_CHANGED (not add+remove) — it is the drift that
 *  matters for dangling/takeover review. */
export function diffDnsSnapshots(before: DnsRecord[], after: DnsRecord[]): DnsChangeEvent[] {
  const events: DnsChangeEvent[] = [];
  const key = (r: DnsRecord) => `${r.type}:${r.value.trim().toLowerCase()}`;
  const bMap = new Map(before.map((r) => [key(r), r]));
  const aMap = new Map(after.map((r) => [key(r), r]));
  const singleValued: DnsRecordType[] = ["CNAME"];
  for (const type of singleValued) {
    const b = before.filter((r) => r.type === type);
    const a = after.filter((r) => r.type === type);
    if (b.length === 1 && a.length === 1 && key(b[0]!) !== key(a[0]!)) {
      events.push({ kind: "DNS_TARGET_CHANGED", recordType: type, before: b[0]!.value, after: a[0]!.value });
      bMap.delete(key(b[0]!));
      aMap.delete(key(a[0]!));
    }
  }
  for (const [k, r] of aMap) if (!bMap.has(k)) events.push({ kind: "DNS_RECORD_ADDED", recordType: r.type, before: null, after: r.value });
  for (const [k, r] of bMap) if (!aMap.has(k)) events.push({ kind: "DNS_RECORD_REMOVED", recordType: r.type, before: r.value, after: null });
  return events.sort((x, y) => `${x.recordType}:${x.kind}:${x.after ?? x.before}`.localeCompare(`${y.recordType}:${y.kind}:${y.after ?? y.before}`));
}

/**
 * §34 wildcard detection: if several lexically-unrelated probe labels
 * all resolve to the same address set, the zone answers everything —
 * candidates minted from such labels are wildcard noise and must not
 * explode the inventory.
 */
export function detectWildcard(probeResults: Array<{ label: string; addresses: string[] }>): { wildcard: boolean; addresses: string[] } {
  const answered = probeResults.filter((p) => p.addresses.length > 0);
  if (answered.length < 2) return { wildcard: false, addresses: [] };
  const first = [...answered[0]!.addresses].sort().join(",");
  const allSame = answered.every((p) => [...p.addresses].sort().join(",") === first);
  return allSame ? { wildcard: true, addresses: answered[0]!.addresses } : { wildcard: false, addresses: [] };
}

/** Known claimable-service CNAME suffixes (observable configuration
 *  only — a match means "target is a service that CAN be unclaimed",
 *  combined with a dead target it becomes a candidate, §29). */
export const CLAIMABLE_SERVICE_SUFFIXES: Array<{ suffix: string; service: string }> = [
  { suffix: ".github.io", service: "GitHub Pages" },
  { suffix: ".herokuapp.com", service: "Heroku" },
  { suffix: ".azurewebsites.net", service: "Azure App Service" },
  { suffix: ".cloudfront.net", service: "CloudFront" },
  { suffix: ".s3.amazonaws.com", service: "Amazon S3 website" },
  { suffix: ".elasticbeanstalk.com", service: "Elastic Beanstalk" },
  { suffix: ".netlify.app", service: "Netlify" },
  { suffix: ".vercel.app", service: "Vercel" },
  { suffix: ".zendesk.com", service: "Zendesk" },
  { suffix: ".myshopify.com", service: "Shopify" },
];

export interface DanglingDnsAssessment {
  isCandidate: boolean;
  service: string | null;
  evidence: string;
}

/**
 * §29/§141: dangling DNS candidate — a CNAME points at a claimable
 * service AND the target observably does not resolve (NXDOMAIN /
 * no addresses). Both conditions are required; a live target is
 * just a normal CNAME. Output is a candidate signal — never a
 * takeover attempt and never an exploitability claim.
 */
export function assessDanglingDns(input: {
  records: DnsRecord[];
  /** Resolution outcome for the CNAME target: "NXDOMAIN" | "NO_ADDRESS" | "RESOLVES" | "UNKNOWN". */
  targetResolution: "NXDOMAIN" | "NO_ADDRESS" | "RESOLVES" | "UNKNOWN";
}): DanglingDnsAssessment {
  const cname = input.records.find((r) => r.type === "CNAME");
  if (!cname) return { isCandidate: false, service: null, evidence: "no CNAME record" };
  const target = cname.value.trim().toLowerCase().replace(/\.$/, "");
  const match = CLAIMABLE_SERVICE_SUFFIXES.find((s) => target.endsWith(s.suffix));
  if (!match) return { isCandidate: false, service: null, evidence: `CNAME target ${target} is not a known claimable-service suffix` };
  if (input.targetResolution === "RESOLVES") {
    return { isCandidate: false, service: match.service, evidence: `CNAME target ${target} (${match.service}) resolves normally` };
  }
  if (input.targetResolution === "UNKNOWN") {
    return { isCandidate: false, service: match.service, evidence: `CNAME target ${target} (${match.service}) resolution unknown — insufficient evidence for a candidate` };
  }
  return {
    isCandidate: true,
    service: match.service,
    evidence: `CNAME target ${target} (${match.service}) does not resolve (${input.targetResolution}); the name may be claimable by a third party — review as a candidate only`,
  };
}
