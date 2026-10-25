"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Detection management (Prompt 28 §107–§114): versioned declarative
 * rules, a structured editor (JSON definition validated server-side
 * by the safe DSL compiler — code-shaped rules are rejected), rule
 * testing against supplied fixture events (§109), the promotion
 * workflow (§111), ATT&CK coverage (§112 — coverage is visibility,
 * not prevention) and detection health (§114).
 */
interface Rule {
  id: string; name: string; status: string; currentVersion: number; severity: string;
  category: string; templateKey?: string | null; matchCount: number; falsePositiveRate: number | null;
  attackMappings: unknown;
}
interface Coverage { coveredTechniques: number; totalTechniques: number; coverageRate: number | null; note: string }

export default function Page() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [health, setHealth] = useState<Array<Record<string, unknown>>>([]);
  const [name, setName] = useState("");
  const [definition, setDefinition] = useState("{\n  \"type\": \"SINGLE_EVENT\",\n  \"conditions\": { \"kind\": \"cond\", \"field\": \"eventAction\", \"op\": \"eq\", \"value\": \"LOGIN\" }\n}");
  const [testEvents, setTestEvents] = useState("[]");
  const [testResult, setTestResult] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const out = await apiFetch<{ items: Rule[] }>("/soc/detections");
      setRules(out.items);
      setCoverage(await apiFetch<Coverage>("/soc/detections/coverage"));
      const h = await apiFetch<{ items: Array<Record<string, unknown>> }>("/soc/detections/health");
      setHealth(h.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const call = async (fn: () => Promise<unknown>, ok: string) => {
    try { await fn(); setNotice(ok); await load(); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Action failed."); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Detection Engineering" title="Detection Engineering" body="Declarative rules only — no shell, SQL or code can exist in a rule (§18). Versions are immutable; edits create a new version (§16)." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <div className="flex flex-wrap gap-2">
        <button className="rounded bg-slate-700 px-3 py-2 text-sm text-white"
          onClick={() => call(() => apiFetch("/soc/detections/seed-templates", { method: "POST", body: JSON.stringify({}) }), "Built-in defensive templates seeded as DRAFT rules (§25).")}>
          Seed built-in templates
        </button>
        {coverage && (
          <span className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-300">
            ATT&CK coverage: {coverage.coveredTechniques}/{coverage.totalTechniques} techniques
            {coverage.coverageRate !== null ? ` (${Math.round(coverage.coverageRate * 100)}%)` : ""} — {coverage.note}
          </span>
        )}
      </div>
      <Card title={`${rules.length} rule(s)`}>
        {rules.length === 0 ? <EmptyState title="No detection rules yet. Seed the built-in templates or create a rule below." body="" /> : (
          <ul className="divide-y divide-slate-800">
            {rules.map((r) => (
              <li key={r.id} className="py-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-slate-100">{r.name}</span>
                  <Badge>{r.status}</Badge><Badge>v{r.currentVersion}</Badge><Badge>{r.severity}</Badge>
                  <span className="text-xs text-slate-500">matches {r.matchCount} · FP rate {r.falsePositiveRate === null ? "—" : `${Math.round(r.falsePositiveRate * 100)}%`}</span>
                </div>
                <div className="mt-1 flex flex-wrap gap-2">
                  {r.status === "DRAFT" && <button className="rounded bg-slate-700 px-2 py-1 text-xs text-white" onClick={() => call(() => apiFetch(`/soc/detections/${r.id}/status`, { method: "POST", body: JSON.stringify({ status: "TESTING" }) }), "Rule moved to TESTING.")}>→ Testing</button>}
                  {r.status === "TESTING" && <button className="rounded bg-emerald-700 px-2 py-1 text-xs text-white" onClick={() => call(() => apiFetch(`/soc/detections/${r.id}/status`, { method: "POST", body: JSON.stringify({ status: "ACTIVE" }) }), "Rule activated (stored version re-compiled, §111).")}>Activate</button>}
                  {r.status === "ACTIVE" && <button className="rounded bg-amber-700 px-2 py-1 text-xs text-white" onClick={() => call(() => apiFetch(`/soc/detections/${r.id}/status`, { method: "POST", body: JSON.stringify({ status: "DISABLED" }) }), "Rule disabled.")}>Disable</button>}
                  {r.status === "DISABLED" && <button className="rounded bg-slate-700 px-2 py-1 text-xs text-white" onClick={() => call(() => apiFetch(`/soc/detections/${r.id}/status`, { method: "POST", body: JSON.stringify({ status: "TESTING" }) }), "Rule back to TESTING.")}>→ Testing</button>}
                  <button className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200" onClick={() => call(async () => {
                    const out = await apiFetch<{ matches: number; nonMatches: number; falsePositiveCandidates: number }>(`/soc/detections/${r.id}/test`, { method: "POST", body: JSON.stringify({ events: JSON.parse(testEvents) }) });
                    setTestResult(`${r.name}: ${out.matches} match(es), ${out.nonMatches} non-match(es), ${out.falsePositiveCandidates} possible-FP — testing never creates alerts (§109).`);
                  }, "Rule test complete.")}>Test with fixture events ↓</button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Create rule — structured definition (validated by the DSL compiler)">
          <div className="space-y-2">
            <input className="w-full rounded bg-slate-800 px-2 py-1 text-sm" placeholder="Rule name" value={name} onChange={(e) => setName(e.target.value)} />
            <textarea className="w-full rounded bg-slate-800 px-2 py-1 font-mono text-xs" rows={8} value={definition} onChange={(e) => setDefinition(e.target.value)} />
            <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white"
              onClick={() => call(() => apiFetch("/soc/detections", { method: "POST", body: JSON.stringify({ name, category: "CUSTOM", severity: "MEDIUM", definition: JSON.parse(definition) }) }), "Rule created as DRAFT v1.")}>
              Create rule
            </button>
          </div>
        </Card>
        <Card title="Rule testing fixtures (§109/§110) + detection health (§114)">
          <div className="space-y-2">
            <textarea className="w-full rounded bg-slate-800 px-2 py-1 font-mono text-xs" rows={5} value={testEvents} onChange={(e) => setTestEvents(e.target.value)} />
            {testResult && <p className="text-sm text-slate-300">{testResult}</p>}
            {health.length > 0 && (
              <ul className="text-sm text-slate-300">
                {health.map((h) => (
                  <li key={String(h.ruleId)}>{String(h.name)}: {(h.issues as string[]).join(", ") || "healthy"}</li>
                ))}
              </ul>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
