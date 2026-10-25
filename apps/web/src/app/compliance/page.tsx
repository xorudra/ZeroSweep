"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Compliance posture (Prompt 13 §88): control assessments from the CIS
 * Docker / CIS Kubernetes / NSA-CISA catalogs. These are posture
 * evidence from governed checks — ZeroSweep never presents them as a
 * compliance certification, and this page carries that line verbatim.
 */
interface AssessmentRow {
  id: string; frameworkKey: string; controlId: string; subjectRef: string;
  status: string; evidence?: string | null; assessedAt?: string;
}

const FRAMEWORKS = ["", "CIS_DOCKER", "CIS_KUBERNETES", "NSA_CISA_KUBERNETES", "CIS_AWS", "CIS_AZURE", "CIS_GCP"] as const;

export default function Page() {
  const [items, setItems] = useState<AssessmentRow[]>([]);
  const [byStatus, setByStatus] = useState<Record<string, number>>({});
  const [disclaimer, setDisclaimer] = useState("");
  const [framework, setFramework] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: AssessmentRow[]; byStatus: Record<string, number>; disclaimer: string }>(
        `/compliance/assessments${framework ? `?frameworkKey=${encodeURIComponent(framework)}` : ""}`,
      );
      setItems(data.items ?? []);
      setByStatus(data.byStatus ?? {});
      setDisclaimer(data.disclaimer ?? "");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [framework]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Compliance" title="Compliance" body="Control assessments from governed container, Kubernetes and multi-cloud checks (CIS Docker, CIS Kubernetes, NSA/CISA hardening guidance, CIS AWS / Azure / GCP Foundations). Framework mappings (NIST, PCI DSS, SOC 2, ISO 27001) are mapping-only — never a certification." />
      <p className="rounded bg-amber-950/60 px-3 py-2 text-sm text-amber-200">{disclaimer || "Control assessments are posture evidence from governed checks; they are not a compliance certification."}</p>
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}

      <Card>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <label className="text-xs text-slate-400">Framework
            <select className="ml-2 rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700" value={framework} onChange={(e) => setFramework(e.target.value)}>
              {FRAMEWORKS.map((f) => <option key={f} value={f}>{f || "All frameworks"}</option>)}
            </select>
          </label>
          <div className="ml-auto flex gap-2">
            {Object.entries(byStatus).map(([status, count]) => <Badge key={status}>{status}: {count}</Badge>)}
          </div>
        </div>
        {items.length === 0 && <EmptyState title="No assessments yet" body="Run a container or Kubernetes scan — passing controls are recorded as evidence, failing controls also raise findings." />}
        <div className="divide-y divide-slate-800">
          {items.map((a) => (
            <div key={a.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge>{a.status}</Badge>
              <span className="font-mono text-slate-300">{a.frameworkKey} · {a.controlId}</span>
              <span className="text-slate-400">{a.subjectRef}</span>
              <span className="ml-auto max-w-md truncate text-xs text-slate-500">{a.evidence ?? ""}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
