import { scrubSecretPatterns, sanitizeUntrustedText } from "./sanitize";
import type { SanitizedFindingView } from "./types";

/**
 * SARIF 2.1.0 export (Prompt 24 §43–§45). CI systems consume this
 * artifact; it is built exclusively from sanitized finding views and
 * scrubbed again at this boundary (§45) — a SARIF file must never
 * carry a secret value, a token, a credential assignment, or an
 * unredacted evidence snippet (§119).
 */

const LEVEL_BY_SEVERITY: Record<string, string> = {
  CRITICAL: "error", HIGH: "error", MEDIUM: "warning", LOW: "note", INFORMATIONAL: "note",
};

export interface SarifExport {
  sarif: Record<string, unknown>;
  redactions: string[];
}

export function buildSarifLog(input: {
  toolName: string;
  toolVersion?: string;
  findings: Array<SanitizedFindingView & { ruleId?: string; cwe?: string }>;
}): SarifExport {
  const redactions: string[] = [];
  const clean = (text: string, max = 500): string => {
    const { text: scrubbed, redactions: r } = scrubSecretPatterns(sanitizeUntrustedText(text, max));
    redactions.push(...r);
    return scrubbed;
  };
  const ruleIds = new Map<string, { id: string; cwe?: string }>();
  const results = input.findings.map((f) => {
    const ruleId = clean(f.ruleId ?? f.id, 120);
    if (!ruleIds.has(ruleId)) ruleIds.set(ruleId, { id: ruleId, cwe: f.cwe });
    return {
      ruleId,
      level: LEVEL_BY_SEVERITY[f.severity] ?? "warning",
      message: { text: clean(`[${f.severity}] ${f.title} (${f.dsrcloneReference})`, 600) },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: clean(f.filePath ?? f.assetReference ?? "unknown", 300) },
          ...(f.startLine ? { region: { startLine: f.startLine } } : {}),
        },
      }],
      partialFingerprints: { dsrcloneFindingId: f.id },
      properties: {
        severity: f.severity,
        status: f.lifecycleStatus,
        kevListed: f.kevListed,
        secretFinding: f.isSecretFinding,
      },
    };
  });
  const rules = [...ruleIds.values()].map((r) => ({
    id: r.id,
    shortDescription: { text: `ZeroSweep rule ${r.id}` },
    ...(r.cwe ? { properties: { tags: [r.cwe] } } : {}),
  }));
  return {
    sarif: {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [{
        tool: { driver: { name: clean(input.toolName, 100), version: input.toolVersion ?? "1.0.0", rules } },
        results,
      }],
    },
    redactions,
  };
}
