import type { OwnerType, OwnershipConfidence } from "./types";

/**
 * Ownership resolution (Prompt 31 §14–§17). Deterministic priority:
 * explicit finding assignment → application owner → repository/service
 * owner → asset owner → workspace default team. Confidence reflects how
 * the owner was established — a manual/explicit assignment is VERIFIED,
 * a workspace default is LOW. The resolver never invents an owner: with
 * no inputs it returns UNKNOWN and no owner. AI suggestions are NOT an
 * input here (§17) — they surface separately and a human confirms them.
 */
export interface OwnershipCandidate {
  ownerType: OwnerType;
  ownerId?: string;
  teamId?: string;
}

export interface OwnershipInputs {
  explicitAssignment?: OwnershipCandidate;
  applicationOwner?: OwnershipCandidate;
  repositoryOwner?: OwnershipCandidate;
  assetOwner?: OwnershipCandidate;
  workspaceDefaultTeam?: OwnershipCandidate;
}

export interface OwnershipResolution extends OwnershipCandidate {
  confidence: OwnershipConfidence;
  source: "EXPLICIT_FINDING_ASSIGNMENT" | "APPLICATION_OWNER" | "REPOSITORY_OWNER" | "ASSET_OWNER" | "WORKSPACE_DEFAULT" | "NONE";
}

const CHAIN: Array<{
  key: keyof OwnershipInputs;
  source: OwnershipResolution["source"];
  confidence: OwnershipConfidence;
}> = [
  { key: "explicitAssignment", source: "EXPLICIT_FINDING_ASSIGNMENT", confidence: "VERIFIED" },
  { key: "applicationOwner", source: "APPLICATION_OWNER", confidence: "HIGH" },
  { key: "repositoryOwner", source: "REPOSITORY_OWNER", confidence: "HIGH" },
  { key: "assetOwner", source: "ASSET_OWNER", confidence: "MEDIUM" },
  { key: "workspaceDefaultTeam", source: "WORKSPACE_DEFAULT", confidence: "LOW" },
];

export function resolveOwnership(inputs: OwnershipInputs): OwnershipResolution {
  for (const step of CHAIN) {
    const candidate = inputs[step.key];
    if (candidate && (candidate.ownerId || candidate.teamId)) {
      return { ...candidate, confidence: step.confidence, source: step.source };
    }
  }
  return { ownerType: "TEAM", confidence: "UNKNOWN", source: "NONE" };
}
