"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card } from "@zerosweep/ui";

/**
 * Computer detail (Prompt 15 §93): OS, delegation configuration,
 * domain-controller role, explainable risk and findings. Posture
 * data only — no remote action of any kind exists for a computer.
 */
interface ComputerDetail {
  id: string; hostname: string; dnsName?: string | null; osName?: string | null; osVersion?: string | null;
  enabled: boolean; isDomainController: boolean; delegationType: string; delegationTargets: string[];
  riskScore?: number | null; riskFactors?: Array<{ factor: string; points: number }> | null;
  findings: Array<{ id: string; title: string; severity: string; ruleId?: string | null; status: string }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [computer, setComputer] = useState<ComputerDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setComputer(await apiFetch<ComputerDetail>(`/ad/computers/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the computer.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!computer) return <p className="text-sm text-slate-400">Loading…</p>;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Directory Computer" title={computer.dnsName ?? computer.hostname} body={`${computer.osName ?? "Unknown OS"} ${computer.osVersion ?? ""}`} />
      <div className="grid md:grid-cols-2 gap-3">
        <Card>
          <h2 className="text-base font-semibold text-slate-100 mb-2">Configuration</h2>
          <ul className="text-sm space-y-1">
            <li className="flex justify-between text-slate-300"><span>Enabled</span><Badge>{computer.enabled ? "YES" : "no"}</Badge></li>
            <li className="flex justify-between text-slate-300"><span>Domain controller</span><Badge>{computer.isDomainController ? "YES" : "no"}</Badge></li>
            <li className="flex justify-between text-slate-300"><span>Delegation</span><span>{computer.delegationType}{(computer.delegationTargets ?? []).length > 0 ? ` → ${computer.delegationTargets.join(", ")}` : ""}</span></li>
          </ul>
        </Card>
        <Card>
          <h2 className="text-base font-semibold text-slate-100 mb-2">Explainable risk (§77)</h2>
          <p className="text-2xl font-semibold text-slate-100">{computer.riskScore ?? "—"}</p>
          {(computer.riskFactors ?? []).map((f) => (
            <p key={f.factor} className="text-sm text-slate-300 flex justify-between"><span>{f.factor}</span><span>+{f.points}</span></p>
          ))}
        </Card>
      </div>
      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Findings</h2>
        {computer.findings.length === 0 ? <p className="text-sm text-slate-400">No findings reference this computer.</p> : (
          <ul className="text-sm space-y-1">
            {computer.findings.map((f) => (
              <li key={f.id} className="text-slate-300"><Badge>{f.severity}</Badge> {f.title} <span className="text-slate-500">{f.ruleId ?? ""} · {f.status}</span></li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
