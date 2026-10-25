"use client";

import { useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface Citation { sourceType: string; sourceId: string; label: string; claimKind?: string; confidence?: number }
interface QaResult {
  response: {
    answer: string; citations: Citation[]; confidence: string; missingData: string[];
    providerName: string; modelName: string; origin: string; insufficientEvidence: boolean;
  };
  conversationId?: string;
  executed: false;
}
interface FindingAnalysis {
  answer: string; citations: Citation[]; confidence: string; limitations: string[];
  structuredOutput?: { claims: { text: string; kind: string }[] };
  agentRun: { status: string; steps: { tool: string; verdict: string }[] };
  executed: false;
}

const TASKS = ["SECURITY_QA", "VULNERABILITY_ANALYSIS", "TREND_ANALYSIS", "EXECUTIVE_SUMMARY"] as const;

/**
 * AI Copilot V2 workspace (Prompt 36 §135): grounded Q&A over the
 * governed pipeline, plus one-click finding analysis via the bounded
 * VulnerabilityAnalysisAgent. Citations link to platform records;
 * confidence, limitations and provider origin (MOCK vs RULE_BASED)
 * are always shown (§140 transparency).
 */
export default function CopilotV2Page() {
  const [query, setQuery] = useState("");
  const [taskType, setTaskType] = useState<string>("SECURITY_QA");
  const [qa, setQa] = useState<QaResult | null>(null);
  const [findingId, setFindingId] = useState("");
  const [analysis, setAnalysis] = useState<FindingAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const ask = async () => {
    setBusy(true); setError(null);
    try {
      setQa(await apiFetch<QaResult>("/ai/copilot", { method: "POST", body: JSON.stringify({ query, taskType }) }));
    } catch (e) { setError((e as Error).message); setQa(null); }
    finally { setBusy(false); }
  };
  const analyze = async () => {
    setBusy(true); setError(null);
    try {
      setAnalysis(await apiFetch<FindingAnalysis>(`/ai/analyze/finding/${findingId}`, { method: "POST", body: "{}" }));
    } catch (e) { setError((e as Error).message); setAnalysis(null); }
    finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader eyebrow="AI Security Copilot V2" title="Copilot workspace"
        body="Answers are grounded in records you are permitted to see, cited, and redacted before any provider call. Untrusted text in records is data, never instructions (§59–§63). The copilot cannot authorize, approve, expand scope or run anything." />
      {error && <p className="mb-4 text-sm text-rose-300">{error}</p>}

      <Card title="Ask (§135)" eyebrow="Grounded security Q&A">
        <div className="mb-2 flex gap-2">
          <select value={taskType} onChange={(e) => setTaskType(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100">
            {TASKS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input value={query} onChange={(e) => setQuery(e.target.value)}
            placeholder="Which critical findings are still open? What changed this week?"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100" />
          <button disabled={busy || query.trim().length < 3} onClick={() => void ask()}
            className="rounded-lg bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">
            {busy ? "Working…" : "Ask"}
          </button>
        </div>
        {qa && (
          <div className="rounded-lg border border-slate-800 p-3">
            <div className="mb-2 flex flex-wrap gap-2">
              <Badge tone={qa.response.insufficientEvidence ? "warn" : "ok"}>{qa.response.insufficientEvidence ? "INSUFFICIENT_EVIDENCE" : qa.response.confidence}</Badge>
              <Badge>{qa.response.origin}</Badge>
              <Badge>executed: false</Badge>
            </div>
            <p className="whitespace-pre-wrap text-sm text-slate-200">{qa.response.answer}</p>
            {qa.response.citations.length > 0 && (
              <ul className="mt-2 space-y-1 text-xs text-slate-400">
                {qa.response.citations.map((c, i) => <li key={i}>[{c.sourceType}] {c.label} <span className="text-slate-500">({c.claimKind ?? "OBSERVED"})</span></li>)}
              </ul>
            )}
            {qa.response.missingData.length > 0 && <p className="mt-2 text-xs text-amber-300">Missing data: {qa.response.missingData.join("; ")}</p>}
          </div>
        )}
      </Card>

      <div className="mt-4">
        <Card title="Analyze a finding (§52)" eyebrow="VulnerabilityAnalysisAgent — bounded steps through the tool gateway">
          <div className="flex gap-2">
            <input value={findingId} onChange={(e) => setFindingId(e.target.value)} placeholder="Finding ID (UUID)"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100" />
            <button disabled={busy || findingId.trim().length < 8} onClick={() => void analyze()}
              className="rounded-lg bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">
              {busy ? "Analyzing…" : "Analyze"}
            </button>
          </div>
          {analysis && (
            <div className="mt-3 rounded-lg border border-slate-800 p-3">
              <div className="mb-2 flex flex-wrap gap-2">
                <Badge tone={analysis.confidence === "INSUFFICIENT_EVIDENCE" ? "warn" : "ok"}>{analysis.confidence}</Badge>
                <Badge>agent: {analysis.agentRun.status}</Badge>
                <Badge>executed: false</Badge>
              </div>
              <p className="whitespace-pre-wrap text-sm text-slate-200">{analysis.answer}</p>
              <ul className="mt-2 space-y-1 text-xs text-slate-400">
                {analysis.agentRun.steps.map((s, i) => <li key={i}>tool {s.tool}: {s.verdict}</li>)}
              </ul>
              {analysis.limitations.length > 0 && <p className="mt-2 text-xs text-amber-300">Limitations: {analysis.limitations.join("; ")}</p>}
            </div>
          )}
          {analysis === null && <div className="mt-3"><EmptyState title="No analysis yet" body="Paste a finding ID from this workspace. Cross-tenant IDs behave as nonexistent (§105)." /></div>}
        </Card>
      </div>
    </>
  );
}
