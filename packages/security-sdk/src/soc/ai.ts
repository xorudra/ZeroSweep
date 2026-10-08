/**
 * SOC AI grounding helpers (Prompt 28 §95–§101). The SOC copilot is
 * a deterministic composer over REAL platform records, in the same
 * discipline as Prompts 21/27: every substantive statement cites the
 * records it came from, missing evidence yields INSUFFICIENT_EVIDENCE,
 * and attribution is NEVER invented (§98/§99/§151). The AI may
 * recommend a predefined response action; it cannot execute one and
 * cannot bypass approval (§96/§152) — recommendations are data, the
 * response engine's policy gate is the only execution path.
 */

export interface SocIncidentFacts {
  incident: { id: string; title: string; status: string; severity: string; priority: string } | null;
  alerts: Array<{ id: string; title: string; severity: string; status: string }>;
  events: Array<{ id: string; eventAction: string; eventTime: string }>;
  assets: Array<{ id: string; label: string }>;
  identities: string[];
  indicators: Array<{ id: string; type: string; valueNormalized: string; confidence: number; sourceName: string }>;
  timeline: Array<{ entryType: string; summary: string; createdAt: string }>;
  actionsTaken: Array<{ actionKey: string; status: string }>;
}

export interface SocAiAnswer {
  status: "OK" | "INSUFFICIENT_EVIDENCE";
  summary: string;
  sections: Record<string, string[]>;
  citations: Array<{ kind: string; id: string }>;
  recommendedPlaybookKey?: string;
  recommendedActions: Array<{ actionKey: string; note: string }>;
  attribution: { claimed: false; note: string };
}

/** §100 structured incident summary + §99 attribution safety. */
export function composeIncidentSummary(facts: SocIncidentFacts): SocAiAnswer {
  const citations: Array<{ kind: string; id: string }> = [];
  if (facts.incident) citations.push({ kind: "INCIDENT", id: facts.incident.id });
  for (const a of facts.alerts.slice(0, 10)) citations.push({ kind: "ALERT", id: a.id });
  for (const e of facts.events.slice(0, 10)) citations.push({ kind: "EVENT", id: e.id });
  for (const i of facts.indicators.slice(0, 10)) citations.push({ kind: "INDICATOR", id: i.id });

  if (!facts.incident && facts.alerts.length === 0 && facts.events.length === 0) {
    return {
      status: "INSUFFICIENT_EVIDENCE",
      summary: "INSUFFICIENT_EVIDENCE: no incident, alert or event records were provided, so no grounded SOC summary can be produced.",
      sections: {}, citations,
      recommendedActions: [],
      attribution: { claimed: false, note: "No attribution is made: there is no evidence to attribute anything to anyone." },
    };
  }
  const sections: Record<string, string[]> = {
    "What happened": facts.timeline.slice(0, 8).map((t) => `${t.createdAt} — ${t.summary}`),
    "Affected assets": facts.assets.map((a) => a.label),
    "Affected identities": facts.identities,
    "Detection basis": facts.alerts.map((a) => `${a.title} (${a.severity}, ${a.status})`),
    "Known evidence": [
      ...facts.events.slice(0, 6).map((e) => `event ${e.eventAction} at ${e.eventTime}`),
      ...facts.indicators.map((i) => `indicator ${i.type} ${i.valueNormalized} — confidence ${i.confidence} from ${i.sourceName} (provenance recorded; not an attribution)`),
    ],
    "Actions taken": facts.actionsTaken.map((a) => `${a.actionKey}: ${a.status}`),
    "Open questions": [
      ...(facts.indicators.length === 0 ? ["No threat-intelligence indicator is linked yet — is external context expected for this incident?"] : []),
      ...(facts.actionsTaken.length === 0 ? ["No response action has been executed yet — is containment required?"] : []),
    ],
    "Current status": facts.incident ? [`${facts.incident.title} is ${facts.incident.status} (severity ${facts.incident.severity}, priority ${facts.incident.priority})`] : [],
  };
  return {
    status: "OK",
    summary: facts.incident
      ? `Incident "${facts.incident.title}" — ${facts.alerts.length} linked alert(s), ${facts.events.length} event(s), ${facts.assets.length} asset(s), ${facts.indicators.length} indicator(s).`
      : `${facts.alerts.length} alert(s) and ${facts.events.length} event(s) in scope.`,
    sections, citations,
    recommendedActions: [],
    attribution: {
      claimed: false,
      note: "No attacker attribution is made. Indicator matches show infrastructure overlap with recorded intelligence (sources cited above); they do not identify a person, group or country (§99).",
    },
  };
}

/** §151: a direct attribution question with insufficient evidence is
 *  refused — always. Attribution requires explicit reliable intel
 *  records, and even then only the recorded confidence/source shows. */
export function answerAttributionQuestion(facts: SocIncidentFacts): SocAiAnswer {
  const withIntel = facts.indicators.filter((i) => i.confidence >= 70);
  if (withIntel.length === 0) {
    return {
      status: "INSUFFICIENT_EVIDENCE",
      summary: "INSUFFICIENT_EVIDENCE: attribution cannot be made from the available records. No high-confidence threat-intelligence record is linked to this activity, and telemetry overlap alone does not identify an actor.",
      sections: { "Evidence limits": ["No linked indicator with confidence ≥ 70.", "Platform telemetry identifies events and infrastructure, not persons or groups."] },
      citations: facts.indicators.map((i) => ({ kind: "INDICATOR", id: i.id })),
      recommendedActions: [],
      attribution: { claimed: false, note: "Attribution refused: unsupported by the recorded evidence (§99/§151)." },
    };
  }
  return {
    status: "OK",
    summary: `Linked intelligence records exist but identify infrastructure, not an actor: ${withIntel.map((i) => `${i.type} ${i.valueNormalized} (confidence ${i.confidence}, source ${i.sourceName})`).join("; ")}. Any attribution statement must quote these sources and confidences verbatim.`,
    sections: {}, citations: withIntel.map((i) => ({ kind: "INDICATOR", id: i.id })),
    recommendedActions: [],
    attribution: { claimed: false, note: "The platform records indicator provenance; it does not assert who operated the infrastructure." },
  };
}

/** §101: deterministic NL → SOC filter translation (no AI SQL, no
 *  free-form query generation — the same discipline as P21/P27). */
export interface SocNaturalQuery { kind: "ALERTS" | "INCIDENTS" | "INDICATOR_MATCHES"; filters: Record<string, string | boolean> }

export function translateSocNaturalQuery(text: string): SocNaturalQuery | null {
  const t = text.toLowerCase();
  const filters: Record<string, string | boolean> = {};
  if (/\bp1\b/.test(t)) filters.priority = "P1";
  if (/\bp2\b/.test(t)) filters.priority = "P2";
  if (/privileged/.test(t)) filters.identityPrivileged = true;
  if (/kev/.test(t)) filters.kev = true;
  if (/critical asset/.test(t)) filters.assetCriticality = "CRITICAL";
  if (/indicator match/.test(t)) return { kind: "INDICATOR_MATCHES", filters };
  if (/incident/.test(t)) return { kind: "INCIDENTS", filters };
  if (/alert/.test(t)) return { kind: "ALERTS", filters };
  return null;
}
