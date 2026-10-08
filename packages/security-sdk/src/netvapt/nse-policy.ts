import { NSE_SCRIPT_CATALOG, nmapScriptPolicy, type NseScriptMeta } from "../network/script-policy";
import type { NetworkVaptProfileKey } from "./types";

/**
 * Nmap script policy V2 (Prompt 33 §37/§38, §142).
 *
 * V2 names the categories the spec uses — SAFE / DISCOVERY / VERSION /
 * VULN_APPROVED may execute; BRUTE / DOS / EXPLOIT /
 * INTRUSIVE_UNAPPROVED are blocked — layered over the Prompt 10
 * catalog classifications WITHOUT weakening them:
 *
 * - SAFE / DISCOVERY / VERSION map to Prompt 10 SAFE scripts (plus
 *   admin-approved REVIEW_REQUIRED discovery scripts, as in V1).
 * - VULN_APPROVED is a small curated set of read-only vulnerability
 *   CHECK scripts (they confirm a condition from protocol evidence;
 *   they carry no payload and exploit nothing). A VULN_APPROVED script
 *   executes only when ALL of these hold: the profile is
 *   NETWORK_VULNERABILITY, the script id is in the workspace's recorded
 *   allowlist, and the caller holds RUN_NETWORK_VULNERABILITY_SCAN.
 *   The Prompt 10 adapter policy still applies downstream at the
 *   worker — V2 approval never edits the V1 catalog.
 * - BRUTE / DOS / EXPLOIT are structural blocks: there is no approval
 *   input that selects them, in any profile, for any role (§45/§161).
 * - Anything intrusive that is not in the curated VULN_APPROVED set is
 *   INTRUSIVE_UNAPPROVED and blocked.
 *
 * Every selection records the exact scripts used (§38).
 */

export type NseCategoryV2 = "SAFE" | "DISCOVERY" | "VERSION" | "VULN_APPROVED" | "BRUTE" | "DOS" | "EXPLOIT" | "INTRUSIVE_UNAPPROVED";

/** Curated VULN_APPROVED checks (§37): read-only condition checks from
 *  the Prompt 10 INTRUSIVE family whose output confirms or clears a
 *  specific known condition. ftp-anon is handled by the protocol
 *  module's profile-gated metadata check instead (§47) and is NOT in
 *  this set. */
export const VULN_APPROVED_SCRIPT_IDS = ["smb-vuln-ms17-010", "ssl-heartbleed"] as const;

const BLOCKED_UPSTREAM_CATEGORIES = new Set(["brute", "dos", "exploit", "malware", "fuzzer"]);

export function categorizeScriptV2(scriptId: string, upstreamCategories: string[] = []): { category: NseCategoryV2; meta: NseScriptMeta } {
  const meta = nmapScriptPolicy.classify(scriptId, upstreamCategories);
  const cats = (upstreamCategories.length ? upstreamCategories : meta.categories).map((c) => c.toLowerCase());
  if (cats.includes("brute")) return { category: "BRUTE", meta };
  if (cats.includes("dos")) return { category: "DOS", meta };
  if (cats.includes("exploit")) return { category: "EXPLOIT", meta };
  if ((VULN_APPROVED_SCRIPT_IDS as readonly string[]).includes(scriptId)) return { category: "VULN_APPROVED", meta };
  if (meta.classification === "DISABLED") {
    // A DISABLED catalog entry outside the explicit attack families is
    // still unapproved-intrusive for V2 purposes.
    return { category: "INTRUSIVE_UNAPPROVED", meta };
  }
  if (meta.classification === "INTRUSIVE") return { category: "INTRUSIVE_UNAPPROVED", meta };
  if (cats.some((c) => BLOCKED_UPSTREAM_CATEGORIES.has(c))) return { category: "INTRUSIVE_UNAPPROVED", meta };
  if (scriptId.includes("version") || cats.includes("version")) return { category: "VERSION", meta };
  if (cats.includes("discovery")) return { category: "DISCOVERY", meta };
  return { category: "SAFE", meta };
}

export interface NseSelectionRequest {
  profileKey: NetworkVaptProfileKey;
  /** Script ids the caller/profile asks for. Empty = the profile's
   *  governed default set (SAFE/DISCOVERY/VERSION from the catalog). */
  requestedScriptIds?: string[];
  /** Admin-approved REVIEW_REQUIRED ids (Prompt 10 discipline). */
  approvedReviewIds?: string[];
  /** Workspace-recorded VULN_APPROVED allowlist (§38). */
  vulnApprovedAllowlist?: string[];
  /** Caller holds RUN_NETWORK_VULNERABILITY_SCAN (§129). */
  vulnerabilityScanPermission?: boolean;
}

export interface NseSelectionResult {
  /** Exact scripts selected — recorded verbatim on the plan (§38). */
  selected: Array<{ id: string; category: NseCategoryV2 }>;
  /** Every refused script with its category + reason (§142). */
  blocked: Array<{ id: string; category: NseCategoryV2; reason: string }>;
}

export function selectNseScriptsV2(request: NseSelectionRequest): NseSelectionResult {
  const selected: NseSelectionResult["selected"] = [];
  const blocked: NseSelectionResult["blocked"] = [];
  const allowlist = new Set(request.vulnApprovedAllowlist ?? []);
  const approvedReview = new Set(request.approvedReviewIds ?? []);

  const consider = (id: string, upstreamCategories: string[] = []) => {
    const { category, meta } = categorizeScriptV2(id, upstreamCategories);
    if (category === "BRUTE" || category === "DOS" || category === "EXPLOIT") {
      blocked.push({ id, category, reason: `${category} scripts are structurally blocked — no profile, approval or role can select them (§37/§45)` });
      return;
    }
    if (category === "INTRUSIVE_UNAPPROVED") {
      blocked.push({ id, category, reason: "Intrusive script is not in the curated VULN_APPROVED set (§37)" });
      return;
    }
    if (category === "VULN_APPROVED") {
      if (request.profileKey !== "NETWORK_VULNERABILITY") {
        blocked.push({ id, category, reason: "VULN_APPROVED scripts require the NETWORK_VULNERABILITY profile (§37)" });
        return;
      }
      if (!allowlist.has(id)) {
        blocked.push({ id, category, reason: "VULN_APPROVED script is not in the recorded workspace allowlist (§38)" });
        return;
      }
      if (!request.vulnerabilityScanPermission) {
        blocked.push({ id, category, reason: "Caller lacks RUN_NETWORK_VULNERABILITY_SCAN (§129)" });
        return;
      }
      selected.push({ id, category });
      return;
    }
    // SAFE / DISCOVERY / VERSION: Prompt 10 selectability still rules —
    // REVIEW_REQUIRED entries need the admin-approved set.
    if (meta.classification === "REVIEW_REQUIRED" && !approvedReview.has(id)) {
      blocked.push({ id, category, reason: "Discovery script requires administrator approval (Prompt 10 REVIEW_REQUIRED discipline)" });
      return;
    }
    selected.push({ id, category });
  };

  if (request.requestedScriptIds && request.requestedScriptIds.length > 0) {
    for (const id of request.requestedScriptIds) consider(id);
  } else {
    // Governed default set: every SAFE catalog script; VULN_APPROVED
    // only when the full gate holds (evaluated per script above).
    for (const meta of NSE_SCRIPT_CATALOG) {
      if (meta.classification === "SAFE") consider(meta.id, meta.categories);
    }
    if (request.profileKey === "NETWORK_VULNERABILITY") {
      for (const id of VULN_APPROVED_SCRIPT_IDS) consider(id);
    }
  }
  return { selected, blocked };
}
