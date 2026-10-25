/**
 * Nmap NSE script governance (Prompt 10 §14). Nmap is NEVER run with
 * broad script categories ("default", "vuln", "brute", "exploit"): every
 * script carries a platform classification, automated profiles may select
 * only SAFE scripts plus REVIEW_REQUIRED scripts an administrator
 * explicitly approved, INTRUSIVE scripts are never automatically
 * selected, and DISABLED scripts are never selected at all. Unknown
 * scripts default to REVIEW_REQUIRED — the absence of a curated entry
 * is never treated as permission (same discipline as Prompt 7 §4).
 */

export type NseClassification = "SAFE" | "REVIEW_REQUIRED" | "INTRUSIVE" | "DISABLED";

export interface NseScriptMeta {
  id: string;
  name: string;
  /** NSE categories the script belongs to upstream. */
  categories: string[];
  classification: NseClassification;
  /** What the script's output becomes: a configuration OBSERVATION, or a
   *  finding of the given class when its output confirms the condition
   *  (decided by network-checks.ts, never by the script alone). */
  produces: "OBSERVATION" | "FINDING";
  vulnClass?: string;
  /** REVIEW_REQUIRED scripts an admin pre-approved for the broader
   *  NETWORK_COMPREHENSIVE / NETWORK_INTERNAL profiles. */
  approvedForComprehensive?: boolean;
}

/** Frozen snapshot reference: a ScanPlan records this; the governed
 *  script set is never changed mid-assessment. */
export const NSE_POLICY_SNAPSHOT = {
  collection: "zerosweep-governed-nse",
  version: "2026.10.1",
  updatedAt: "2026-10-01T00:00:00.000Z",
} as const;

const S = (partial: Partial<NseScriptMeta> & Pick<NseScriptMeta, "id" | "name" | "classification">): NseScriptMeta => ({
  categories: [], produces: "OBSERVATION", ...partial,
});

export const NSE_SCRIPT_CATALOG: NseScriptMeta[] = [
  // --- SAFE: pure information gathering / configuration observation ---
  S({ id: "banner", name: "Banner Grab", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "ssh-hostkey", name: "SSH Host Key", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "ssh2-enum-algos", name: "SSH Algorithm Enumeration", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "ssl-cert", name: "SSL Certificate Information", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "ssl-enum-ciphers", name: "SSL Cipher Enumeration", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "http-server-header", name: "HTTP Server Header", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "http-title", name: "HTTP Title", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "smb-os-discovery", name: "SMB OS Discovery", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "dns-nsid", name: "DNS NSID", categories: ["discovery", "safe"], classification: "SAFE" }),
  S({ id: "ftp-syst", name: "FTP System Type", categories: ["discovery", "safe"], classification: "SAFE" }),
  // --- SAFE checks whose output can CONFIRM a finding (§37/§41) ---
  S({ id: "smb2-security-mode", name: "SMB2 Security Mode", categories: ["discovery", "safe"], classification: "SAFE", produces: "FINDING", vulnClass: "SMB_SIGNING_NOT_REQUIRED" }),
  S({ id: "ssl-date", name: "SSL Certificate Date Check", categories: ["discovery", "safe"], classification: "SAFE" }),
  // --- REVIEW_REQUIRED: interpretation-sensitive, admin-approved only ---
  S({ id: "smb-security-mode", name: "SMB Security Mode (v1)", categories: ["discovery", "safe"], classification: "REVIEW_REQUIRED", produces: "FINDING", vulnClass: "SMB_SIGNING_NOT_REQUIRED", approvedForComprehensive: true }),
  S({ id: "snmp-info", name: "SNMP System Info", categories: ["discovery", "safe"], classification: "REVIEW_REQUIRED", approvedForComprehensive: true }),
  S({ id: "rdp-ntlm-info", name: "RDP NTLM Info", categories: ["discovery", "safe"], classification: "REVIEW_REQUIRED", approvedForComprehensive: true }),
  // --- INTRUSIVE: vulnerability probing — never auto-selected (§14) ---
  S({ id: "smb-vuln-ms17-010", name: "SMB MS17-010 Vulnerability Check", categories: ["vuln", "intrusive"], classification: "INTRUSIVE", produces: "FINDING" }),
  S({ id: "ssl-heartbleed", name: "SSL Heartbleed Check", categories: ["vuln", "intrusive"], classification: "INTRUSIVE", produces: "FINDING" }),
  S({ id: "http-vuln-cve2011-3192", name: "HTTP Apache Byte-Range DoS Check", categories: ["vuln", "intrusive"], classification: "INTRUSIVE", produces: "FINDING" }),
  S({ id: "ftp-anon", name: "FTP Anonymous Login Check", categories: ["auth", "intrusive"], classification: "INTRUSIVE", produces: "FINDING" }),
  // --- DISABLED: credential attacks / exploitation / DoS — never run ---
  S({ id: "ssh-brute", name: "SSH Brute Force", categories: ["brute", "intrusive"], classification: "DISABLED" }),
  S({ id: "smb-brute", name: "SMB Brute Force", categories: ["brute", "intrusive"], classification: "DISABLED" }),
  S({ id: "ftp-brute", name: "FTP Brute Force", categories: ["brute", "intrusive"], classification: "DISABLED" }),
  S({ id: "http-slowloris-check", name: "HTTP Slowloris DoS Check", categories: ["dos", "vuln"], classification: "DISABLED" }),
  S({ id: "smb-psexec", name: "SMB PsExec Exploitation", categories: ["exploit", "intrusive"], classification: "DISABLED" }),
];

/** Category heuristics for scripts NOT in the curated catalog: anything
 *  touching brute force, exploitation or denial of service is classified
 *  at least INTRUSIVE (DISABLED for the pure attack families); "vuln"
 *  probes are INTRUSIVE; everything unknown stays REVIEW_REQUIRED. */
const DISABLED_CATEGORY = ["brute", "exploit", "dos", "malware"];
const INTRUSIVE_CATEGORY = ["vuln", "intrusive", "auth", "fuzzer"];

export class NmapScriptPolicy {
  private readonly byId = new Map(NSE_SCRIPT_CATALOG.map((s) => [s.id, s]));

  classify(scriptId: string, categories: string[] = []): NseScriptMeta {
    const known = this.byId.get(scriptId);
    if (known) return known;
    const cats = categories.map((c) => c.toLowerCase());
    let classification: NseClassification = "REVIEW_REQUIRED";
    if (cats.some((c) => DISABLED_CATEGORY.includes(c))) classification = "DISABLED";
    else if (cats.some((c) => INTRUSIVE_CATEGORY.includes(c))) classification = "INTRUSIVE";
    return { id: scriptId, name: scriptId, categories: cats, classification, produces: "OBSERVATION" };
  }

  /** Scripts an automated profile may run: SAFE always; REVIEW_REQUIRED
   *  only when the id is in the administrator-approved set. INTRUSIVE and
   *  DISABLED can NEVER be selected — not even when "approved" (§14):
   *  approval lists containing them are silently stripped here and the
   *  exclusion is counted for the plan record. */
  selectScripts(approvedReviewIds: string[] = []): { selected: NseScriptMeta[]; excludedIntrusive: number; excludedDisabled: number } {
    const approved = new Set(approvedReviewIds);
    const selected: NseScriptMeta[] = [];
    let excludedIntrusive = 0;
    let excludedDisabled = 0;
    for (const meta of NSE_SCRIPT_CATALOG) {
      if (meta.classification === "SAFE") selected.push(meta);
      else if (meta.classification === "REVIEW_REQUIRED" && approved.has(meta.id)) selected.push(meta);
      else if (meta.classification === "INTRUSIVE") excludedIntrusive++;
      else if (meta.classification === "DISABLED") excludedDisabled++;
    }
    return { selected, excludedIntrusive, excludedDisabled };
  }

  isSelectable(scriptId: string, approvedReviewIds: string[] = []): boolean {
    const meta = this.classify(scriptId);
    if (meta.classification === "SAFE") return true;
    if (meta.classification === "REVIEW_REQUIRED") return approvedReviewIds.includes(scriptId);
    return false;
  }
}

export const nmapScriptPolicy = new NmapScriptPolicy();

/** REVIEW_REQUIRED scripts pre-approved for the broader network profiles
 *  (§11): comprehensive/internal scans carry the admin-approved set;
 *  discovery/baseline profiles run SAFE scripts only. Worker-derived
 *  from the profile — never client input. */
export function approvedNseIdsForProfile(profile: string): string[] {
  if (profile === "NETWORK_COMPREHENSIVE" || profile === "NETWORK_INTERNAL") {
    return NSE_SCRIPT_CATALOG.filter((s) => s.classification === "REVIEW_REQUIRED" && s.approvedForComprehensive).map((s) => s.id);
  }
  return [];
}
