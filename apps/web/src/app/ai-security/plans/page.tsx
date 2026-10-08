"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface Workflow {
  id: string; taskType: string; objective: string; status: string; mode: string;
  authorizationSnapshotHash: string; createdAt: string;
  validation?: { verdict: string; findings: { severity: string; reason: string }[] };
}

/**
 * AI plans & workflows (Prompt 36 §137): plans are composed
 * deterministically, validated against the immutable authorization
 * snapshot (§43/§46) and only run after a recorded human approval
 * (§48). AI authorship never implies authorization.
 */
export default function AiPlansPage() {
  const [rows, setRows] = useState<Workflow[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [objective, setObjective] = useState("");
  const [profile, setProfile] = useState("WEB_BASELINE");
  const [targetIds, setTargetIds] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = () => { apiFetch<Workflow[]>("/ai/plans").then(setRows).catch((e: Error) => setError(e.message)); };
  useEffect(load, []);

  const create = async () => {
    setBusy(true); setError(null); setNotice(null);
    try {
      const out = await apiFetch<{ workflow: Workflow; validation: { verdict: string } }>("/ai/plans", {
        method: "POST",
        body: JSON.stringify({
          taskType: "SCAN_PLAN_DRAFT", objective: objective || undefined, profile,
          targetIds: targetIds.split(",").map((s) => s.trim()).filter(Boolean),
        }),
      });
      setNotice(`Plan created — validator verdict ${out.validation.verdict}, workflow status ${out.workflow.status}. Execution still requires approval.`);
      load();
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader eyebrow="AI Security Copilot V2" title="Plans & workflows"
        body="Every plan binds the authorization snapshot hash it was validated against. If authorization drifts, execution re-validation fails closed (§150) — nothing runs." />
      {error && <p className="mb-4 text-sm text-rose-300">{error}</p>}
      {notice && <p className="mb-4 text-sm text-emerald-300">{notice}</p>}

      <Card title="Draft a scan plan (§74/§75)" eyebrow="Safe default profile unless you choose an approved one">
        <div className="flex flex-wrap gap-2">
          <input value={objective} onChange={(e) => setObjective(e.target.value)} placeholder="Objective (optional)"
            className="min-w-56 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100" />
          <input value={profile} onChange={(e) => setProfile(e.target.value)} placeholder="Profile"
            className="w-52 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100" />
          <input value={targetIds} onChange={(e) => setTargetIds(e.target.value)} placeholder="Target IDs (comma-separated)"
            className="min-w-56 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100" />
          <button disabled={busy} onClick={() => void create()}
            className="rounded-lg bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">
            {busy ? "Validating…" : "Create plan"}
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500">Targets must be VERIFIED with an APPROVED assessment in this workspace — the validator rejects anything else, including names that merely look like targets.</p>
      </Card>

      <div className="mt-4">
        <Card title="Workflows" eyebrow="Newest first">
          {rows === null ? <EmptyState title="Loading…" body="Fetching governed data for this workspace." /> : rows.length === 0 ? (
            <EmptyState title="No plans yet" body="Draft one above. High-impact profiles require explicit approval and may still be policy-rejected." />
          ) : (
            <ul className="divide-y divide-slate-800">
              {rows.map((w) => (
                <li key={w.id} className="flex items-center justify-between py-2 text-sm">
                  <div>
                    <Link href={`/ai-security/plans/${w.id}`} className="text-cyan-300 hover:underline">{w.objective}</Link>
                    <p className="text-xs text-slate-500">{w.taskType} · snapshot {w.authorizationSnapshotHash.slice(0, 12)}… · {new Date(w.createdAt).toLocaleString()}</p>
                  </div>
                  <Badge tone={w.status === "COMPLETED" ? "ok" : w.status === "REJECTED" || w.status === "FAILED" ? "danger" : "warn"}>{w.status}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
