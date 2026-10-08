"use client";

import { useState } from "react";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

export interface AiResponseView {
  answer: string;
  confidence?: string;
  origin?: string;
  status?: string;
  citations?: { sourceType: string; sourceId: string }[];
  missingData?: string[];
  insufficientEvidence?: boolean;
}

/**
 * Grounded AI response renderer (Prompt 21 §24/§79). Model output is
 * rendered as PLAIN TEXT only — never as HTML — and always labelled
 * with its origin (MODEL vs RULE_BASED vs refusal) and confidence, so
 * deterministic summaries are never mistaken for AI output.
 */
export function AiResponseBlock({ response }: { response: AiResponseView }) {
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2">
        <Badge tone={response.origin === "MODEL" ? "info" : "neutral"}>{response.origin === "MODEL" ? "AI model" : response.origin === "RULE_BASED" ? "Rule-based (no AI provider)" : "No answer"}</Badge>
        {response.confidence && <Badge tone="neutral">confidence: {response.confidence}</Badge>}
        {response.status && <Badge tone={response.status === "COMPLETED" ? "success" : "warning"}>{response.status}</Badge>}
        {response.insufficientEvidence && <Badge tone="warning">INSUFFICIENT_EVIDENCE</Badge>}
      </div>
      <p className="whitespace-pre-wrap text-sm text-slate-300">{response.answer}</p>
      {(response.citations?.length ?? 0) > 0 && (
        <div className="text-xs text-slate-400">
          <p className="font-semibold text-slate-300">Citations</p>
          <ul className="list-disc pl-5">
            {response.citations!.map((c, i) => <li key={i}>{c.sourceType}: {c.sourceId}</li>)}
          </ul>
        </div>
      )}
      {(response.missingData?.length ?? 0) > 0 && (
        <p className="text-xs text-amber-300">Missing data: {response.missingData!.join("; ")}</p>
      )}
    </div>
  );
}

const ACTIONS = [
  { key: "explain", label: "Explain with AI", path: "explain" },
  { key: "remediation", label: "Suggest remediation", path: "remediation" },
  { key: "risk", label: "Explain risk", path: "risk-explanation" },
  { key: "secure-code", label: "Draft secure fix", path: "secure-code" },
] as const;

/** §111 finding-detail AI panel. Every action is an analysis request;
 *  the copilot cannot execute anything from here (§7/§120). */
export function FindingAiPanel({ findingId }: { findingId: string }) {
  const [response, setResponse] = useState<AiResponseView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const run = async (path: string, key: string) => {
    setBusy(key); setError(null);
    try {
      setResponse(await apiFetch<AiResponseView>(`/ai/findings/${findingId}/${path}`, { method: "POST", body: "{}" }));
    } catch (e) {
      setError((e as Error).message);
    } finally { setBusy(null); }
  };

  return (
    <Card title="AI Copilot — analyst assistant (Prompt 21)">
      <p className="text-sm text-slate-400">
        Grounded explanations over this finding&apos;s stored evidence only. The copilot cannot run scans,
        commands or SQL — it explains, summarizes and drafts remediation for human review.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {ACTIONS.map((a) => (
          <button key={a.key} disabled={busy !== null} onClick={() => void run(a.path, a.key)}
            className="rounded-lg bg-cyan-500/10 px-3 py-1.5 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">
            {busy === a.key ? "Working…" : a.label}
          </button>
        ))}
      </div>
      {error && <p className="mt-3 text-sm text-rose-300">{error}</p>}
      {response && <div className="mt-4"><AiResponseBlock response={response} /></div>}
    </Card>
  );
}
