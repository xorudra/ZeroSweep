"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface ModelCap {
  name: string; providerType: string; modelName: string; availability: string;
  structuredOutputSupport: boolean; toolCallingSupport: boolean; embeddingSupport: boolean;
  costClass: string; latencyClass: string;
}
interface Capabilities { routing: { allowedModelIds: string[]; dataResidencyRegion: string | null; allowExternalProviders: boolean; approvalPolicy: string }; models: ModelCap[] }
interface Observability {
  requests: number; totalTokens: number; estimatedCostUsd: number | null; errorRate: number;
  insufficientEvidenceRate: number; approvalRate: number | null;
  approvals: { total: number; decided: number; approved: number };
  workflows?: never;
}
interface TraceRow { id: string; taskType: string; createdAt: string; toolCalls: { tool: string; verdict: string }[] }
interface EvaluationRow { id: string; suite: string; passed: number; failed: number; createdAt: string }

/**
 * AI Security V2 dashboard (Prompt 36 §134): provider/model
 * capabilities with honest availability, router policy, usage and
 * cost (null — never invented — when providers report no cost
 * metadata), approval queue, traces and evaluation status. The
 * copilot analyzes and drafts; it executes nothing (§26).
 */
export default function AiSecurityPage() {
  const [caps, setCaps] = useState<Capabilities | null>(null);
  const [obs, setObs] = useState<Observability | null>(null);
  const [traces, setTraces] = useState<TraceRow[] | null>(null);
  const [evals, setEvals] = useState<EvaluationRow[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Capabilities>("/ai/router/models").then(setCaps).catch((e: Error) => setError(e.message));
    apiFetch<Observability>("/ai/observability").then(setObs).catch(() => undefined);
    apiFetch<TraceRow[]>("/ai/traces").then(setTraces).catch(() => undefined);
    apiFetch<EvaluationRow[]>("/ai/evaluations").then(setEvals).catch(() => undefined);
  }, []);

  return (
    <>
      <PageHeader eyebrow="AI Security Copilot V2" title="AI security"
        body="Governed analyst automation over platform data: model routing by capability, permission-aware retrieval, a typed tool gateway, validated plans with human approval, and bounded agents. executed: false — always." />
      {error && <p className="mb-4 text-sm text-rose-300">{error}</p>}

      <div className="mb-4 flex flex-wrap gap-2 text-sm">
        <Link className="rounded-lg bg-cyan-500/10 px-3 py-2 text-cyan-300 hover:bg-cyan-500/20" href="/ai-security/copilot">Copilot V2 (§135)</Link>
        <Link className="rounded-lg bg-cyan-500/10 px-3 py-2 text-cyan-300 hover:bg-cyan-500/20" href="/ai-security/plans">Plans &amp; workflows (§137)</Link>
        <Link className="rounded-lg bg-cyan-500/10 px-3 py-2 text-cyan-300 hover:bg-cyan-500/20" href="/ai-security/approvals">Approvals (§138)</Link>
        <Link className="rounded-lg bg-cyan-500/10 px-3 py-2 text-cyan-300 hover:bg-cyan-500/20" href="/ai">V1 dashboard</Link>
      </div>

      <Card title="Model capabilities & routing (§5/§6)" eyebrow="Providers show status only — credentials are reference names, never values">
        {caps === null ? <EmptyState title="Loading…" body="Fetching governed data for this workspace." /> : caps.models.length === 0 ? (
          <EmptyState title="No models configured" body="Add a provider and model under the V1 AI settings. Routing reports NOT_CONFIGURED until a capable, enabled model exists — it never silently substitutes one." />
        ) : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Model</th><th>Provider</th><th>Availability</th><th>Structured</th><th>Tools</th><th>Embeddings</th><th>Cost</th><th>Latency</th></tr></thead>
            <tbody>
              {caps.models.map((m) => (
                <tr key={m.name + m.modelName} className="border-t border-slate-800">
                  <td className="py-1 text-slate-100">{m.modelName}</td><td>{m.providerType}</td>
                  <td><Badge tone={m.availability === "AVAILABLE" ? "ok" : "warn"}>{m.availability}</Badge></td>
                  <td>{m.structuredOutputSupport ? "yes" : "no"}</td><td>{m.toolCallingSupport ? "yes" : "no"}</td>
                  <td>{m.embeddingSupport ? "yes" : "no"}</td><td>{m.costClass}</td><td>{m.latencyClass}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {caps && (
          <p className="mt-3 text-xs text-slate-400">
            Policy: approvals = {caps.routing.approvalPolicy} · external providers {caps.routing.allowExternalProviders ? "allowed (SECRET data still never leaves — §6)" : "disabled by workspace policy"} ·
            residency {caps.routing.dataResidencyRegion ?? "not pinned"} · allowlist {caps.routing.allowedModelIds.length ? `${caps.routing.allowedModelIds.length} model(s)` : "all enabled models"}.
          </p>
        )}
      </Card>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Card title="Usage, cost & approvals (§121–§124, §128)" eyebrow="Observability">
          {obs === null ? <EmptyState title="Loading…" body="Fetching governed data for this workspace." /> : (
            <ul className="space-y-1 text-sm text-slate-300">
              <li>Requests (sampled ≤5000): <b className="text-slate-100">{obs.requests}</b></li>
              <li>Total tokens: <b className="text-slate-100">{obs.totalTokens}</b></li>
              <li>Estimated cost: <b className="text-slate-100">{obs.estimatedCostUsd === null ? "not reported by provider metadata — never invented" : `$${obs.estimatedCostUsd}`}</b></li>
              <li>Error rate: {(obs.errorRate * 100).toFixed(1)}% · insufficient-evidence rate: {(obs.insufficientEvidenceRate * 100).toFixed(1)}%</li>
              <li>Approvals: {obs.approvals.approved}/{obs.approvals.decided} approved of {obs.approvals.total} requested</li>
            </ul>
          )}
        </Card>
        <Card title="Latest evaluations (§100–§103)" eyebrow="Measured results only">
          {evals === null ? <EmptyState title="Loading…" body="Fetching governed data for this workspace." /> : evals.length === 0 ? (
            <EmptyState title="No evaluation runs yet" body="Run the V2 red-team suite from the API (POST /ai/evaluations/run-v2) — it executes tenant-isolation, injection, tool-safety, plan-validity and grounding cases against the real governors." />
          ) : (
            <ul className="space-y-1 text-sm text-slate-300">
              {evals.map((e) => (
                <li key={e.id} className="flex items-center justify-between">
                  <span>{e.suite}</span>
                  <Badge tone={e.failed === 0 ? "ok" : "danger"}>{e.passed} passed · {e.failed} failed</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4">
        <Card title="Recent traces (§130)" eyebrow="Sanitized metadata — prompts, responses and tool arguments are never stored in traces">
          {traces === null ? <EmptyState title="Loading…" body="Fetching governed data for this workspace." /> : traces.length === 0 ? (
            <EmptyState title="No traces yet" body="Every copilot, agent, gateway and workflow run records a sanitized trace here." />
          ) : (
            <ul className="space-y-1 text-sm text-slate-300">
              {traces.slice(0, 10).map((t) => (
                <li key={t.id} className="flex items-center justify-between">
                  <span>{t.taskType}</span>
                  <span className="text-slate-500">{new Date(t.createdAt).toLocaleString()} · {(t.toolCalls ?? []).length} tool call(s)</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
