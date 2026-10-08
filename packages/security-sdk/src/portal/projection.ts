import { redactClientText } from "../reporting2/redaction";
import { toV2LifecycleState } from "../reporting2/lifecycle-view";

/**
 * Prompt 37 §100/§101/§109: the client projection.
 *
 * This is the ONLY shape of finding data that may cross into the
 * client portal. It is an allowlist projection, not a filtered copy:
 * fields that are not listed here do not exist for clients. Internal
 * comments (§34), restricted evidence (§39), scanner internals, risk
 * internals and other clients' data cannot leak through a field the
 * projection never reads. All free text passes the client redactor.
 */
export interface ClientEvidenceInput {
  id: string;
  visibility: string; // INTERNAL | CLIENT | REPORT | RESTRICTED
  summary?: string | null;
  evidenceType: string;
  createdAt: Date | string;
}
export interface ClientCommentInput {
  id: string;
  visibility: string; // INTERNAL | CLIENT
  authorId: string;
  text: string;
  createdAt: Date | string;
}
export interface ClientFindingInput {
  id: string;
  title: string;
  description: string;
  severity: string;
  riskScore?: number | null;
  cve?: string | null;
  cwe?: string | null;
  cvssScore?: number | null;
  epssScore?: number | null;
  kevListed?: boolean;
  host?: string | null;
  endpoint?: string | null;
  technicalImpact?: string | null;
  businessImpact?: string | null;
  remediation?: string | null;
  lifecycleStatus: string;
  caseStatus?: string | null;
  caseVerificationState?: string | null;
  verificationStatus?: string | null;
  dueAt?: Date | string | null;
  createdAt: Date | string;
}

export interface ClientFindingView {
  id: string;
  title: string;
  description: string;
  severity: string;
  riskScore: number | null;
  cve: string | null;
  cwe: string | null;
  cvssScore: number | null;
  epssScore: number | null;
  kevListed: boolean;
  affectedAsset: string | null;
  impact: string | null;
  remediation: string | null;
  status: string; // V2 lifecycle vocabulary (§7)
  verification: string;
  dueAt: string | null;
  discoveredAt: string;
  evidence: { id: string; summary: string; type: string; createdAt: string }[];
  comments: { id: string; authorId: string; text: string; createdAt: string }[];
}

const CLIENT_EVIDENCE_VISIBILITY = new Set(["CLIENT", "REPORT"]);

export function projectFindingForClient(
  finding: ClientFindingInput,
  evidence: ClientEvidenceInput[],
  comments: ClientCommentInput[],
): ClientFindingView {
  return {
    id: finding.id,
    title: redactClientText(finding.title),
    description: redactClientText(finding.description),
    severity: finding.severity,
    riskScore: finding.riskScore ?? null,
    cve: finding.cve ?? null,
    cwe: finding.cwe ?? null,
    cvssScore: finding.cvssScore ?? null,
    epssScore: finding.epssScore ?? null,
    kevListed: finding.kevListed ?? false,
    affectedAsset: finding.host ?? finding.endpoint ?? null,
    impact: redactClientText(finding.businessImpact ?? finding.technicalImpact ?? "") || null,
    remediation: finding.remediation ? redactClientText(finding.remediation) : null,
    status: toV2LifecycleState({
      lifecycleStatus: finding.lifecycleStatus,
      caseStatus: finding.caseStatus,
      caseVerificationState: finding.caseVerificationState,
      verificationStatus: finding.verificationStatus,
    }),
    verification: finding.caseVerificationState ?? finding.verificationStatus ?? "UNVERIFIED",
    dueAt: finding.dueAt ? new Date(finding.dueAt).toISOString() : null,
    discoveredAt: new Date(finding.createdAt).toISOString(),
    evidence: evidence
      .filter((e) => CLIENT_EVIDENCE_VISIBILITY.has(e.visibility))
      .map((e) => ({
        id: e.id,
        summary: redactClientText(e.summary ?? ""),
        type: e.evidenceType,
        createdAt: new Date(e.createdAt).toISOString(),
      })),
    comments: comments
      .filter((c) => c.visibility === "CLIENT")
      .map((c) => ({
        id: c.id,
        authorId: c.authorId,
        text: redactClientText(c.text),
        createdAt: new Date(c.createdAt).toISOString(),
      })),
  };
}

/** §109: notification text is built from the projection only. */
export function clientNotificationText(kind: string, view: Pick<ClientFindingView, "title" | "severity" | "status">): { title: string; body: string } {
  switch (kind) {
    case "FINDING_PUBLISHED":
      return { title: "New finding shared with you", body: `${view.title} (${view.severity}) is now visible in your portal.` };
    case "VERIFICATION_RESULT":
      return { title: "Verification result available", body: `${view.title} is now ${view.status}.` };
    case "SLA_APPROACHING":
      return { title: "Remediation deadline approaching", body: `${view.title} (${view.severity}) is approaching its remediation deadline.` };
    default:
      return { title: "Portal update", body: view.title };
  }
}
