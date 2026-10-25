"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Attack paths (Prompt 15 §95): defensive MODELS computed over
 * collected directory data. This page is display-only BY DESIGN —
 * there is no execute, validate or exploit control here or anywhere
 * in the product (§35/§120). A path never implies a principal or
 * system is compromised (§75/§76); statuses are THEORETICAL,
 * EVIDENCE_BACKED, REVIEWED or MITIGATED — never COMPROMISED.
 */
interface PathRow {
  id: string; title: string; status: string; confidence: string; riskScore: number;
  steps: Array<{ fromRef: string; relationship: string; toRef: string; source: string; confidence: string }>;
  riskFactors: Record<string, number>; createdAt: string;
}
interface PathsData { framing: string; items: PathRow[] }

export default function Page() {
  const [data, setData] = useState<PathsData>({ framing: "", items: [] });
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<PathsData>("/ad/attack-paths"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load attack paths.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Attack Path Analysis"
        title="Attack Paths (modeled)"
        body={data.framing || "Attack paths are defensive models over collected directory data. They are never executed."}
      />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {data.items.length === 0 ? (
        <EmptyState title="No attack paths modeled" body="Paths appear after a collection + graph analysis. No path is ever executed — analysis only." />
      ) : (
        data.items.map((p) => (
          <Card key={p.id}>
            <div className="flex items-center justify-between">
              <h2 className="text-base font-semibold text-slate-100">{p.title}</h2>
              <span className="space-x-2">
                <Badge>{p.status}</Badge><Badge>{p.confidence}</Badge>
                <span className="text-sm text-slate-300">risk {p.riskScore}</span>
              </span>
            </div>
            <ol className="text-sm mt-2 space-y-1">
              {(p.steps ?? []).map((s, i) => (
                <li key={i} className="text-slate-300 font-mono text-xs">
                  {s.fromRef} —{s.relationship}→ {s.toRef}
                  <span className="text-slate-500"> (evidence: {s.source}, {s.confidence})</span>
                </li>
              ))}
            </ol>
            {p.riskFactors && Object.keys(p.riskFactors).length > 0 && (
              <p className="text-xs text-slate-400 mt-2">
                Risk factors (§37): {Object.entries(p.riskFactors).map(([k, v]) => `${k} ${v}`).join(" · ")} —
                path risk is explainable, not a shortest-path guess.
              </p>
            )}
          </Card>
        ))
      )}
    </div>
  );
}
