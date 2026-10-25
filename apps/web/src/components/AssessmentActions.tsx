"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, apiFetch, ApiError } from "@/lib/api-client";
import { Card } from "@zerosweep/ui";

/**
 * Assessment → Plan → Start flow (Prompt 4 §45–§47). For APPROVED assessments:
 * preview the orchestration plan (stages, dependencies, selected adapters —
 * executes nothing) and start a scan. Mock-backed profiles are labelled
 * Simulation / Development Mode, exactly as the backend reports them.
 */
interface AssessmentRow { id: string; name: string; profile: string; status: string }
interface PlanPreview {
  stages: { type: string; dependencies: string[]; selectedAdapters: { slug: string; simulation?: boolean }[] }[];
  selectedTools: string[];
  simulation: boolean;
}

export function AssessmentActions() {
  const router = useRouter();
  const [rows, setRows] = useState<AssessmentRow[]>([]);
  const [plan, setPlan] = useState<PlanPreview | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<{ items: AssessmentRow[] }>("/assessments")
      .then((res) => setRows((res.items ?? []).filter((a) => a.status === "APPROVED")))
      .catch(() => setRows([]));
  }, []);

  if (rows.length === 0) return null;

  const preview = async (id: string) => {
    setBusy(`plan-${id}`);
    try {
      setPlan(await api.planPreview(id) as PlanPreview);
      setMessage(null);
    } catch (e) {
      setMessage(e instanceof ApiError ? e.message : "Plan preview failed");
    } finally { setBusy(null); }
  };

  const start = async (id: string) => {
    setBusy(`start-${id}`);
    try {
      const res = await api.startScan(id);
      router.push(`/scans/${res.scanId}`);
    } catch (e) {
      setMessage(e instanceof ApiError ? e.message : "Start scan failed — the backend re-checks verification, approval and scope before queueing anything.");
    } finally { setBusy(null); }
  };

  return (
    <div className="mt-6 space-y-4">
      <Card>
        <h3 className="text-sm font-semibold text-slate-900">Approved assessments — plan & start</h3>
        <p className="mt-1 text-xs text-slate-500">
          Starting a scan re-validates target verification, approval and scope on the server, builds the
          stage DAG, and queues it for a worker. In this phase only mock-backed profiles execute —
          Simulation / Development Mode.
        </p>
        <div className="mt-3 space-y-2">
          {rows.map((a) => (
            <div key={a.id} className="flex flex-wrap items-center gap-3">
              <span className="text-sm text-slate-900">{a.name}</span>
              <span className="text-xs text-slate-500">{a.profile}</span>
              <button disabled={busy !== null} onClick={() => void preview(a.id)} className="rounded bg-slate-900 px-3 py-1 text-xs text-white disabled:opacity-50">Preview plan</button>
              <button disabled={busy !== null} onClick={() => void start(a.id)} className="rounded bg-sky-600 px-3 py-1 text-xs text-white disabled:opacity-50">Start scan (simulation)</button>
            </div>
          ))}
        </div>
        {message && <p className="mt-3 text-sm text-red-700">{message}</p>}
      </Card>
      {plan && (
        <Card>
          <h4 className="text-sm font-semibold text-slate-900">Plan preview {plan.simulation && <span className="text-amber-700">— Simulation / Development Mode</span>}</h4>
          <ul className="mt-2 space-y-1">
            {plan.stages.map((s) => (
              <li key={s.type} className="text-xs text-slate-600">
                {s.type} · depends on: {s.dependencies.join(", ") || "—"} · adapters: {s.selectedAdapters.map((a) => a.slug).join(", ") || "platform stage"}
              </li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-slate-500">Selected tools: {plan.selectedTools.join(", ") || "none"} · This preview executed nothing.</p>
        </Card>
      )}
    </div>
  );
}
