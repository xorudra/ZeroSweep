"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card } from "@dsrclone/ui";

/**
 * User detail (Prompt 15 §92): account flags, group memberships,
 * delegation, explainable risk and findings. Credential MATERIAL is
 * never part of this view — directory rows hold none by
 * construction (§113), and authentication timestamps are metadata.
 */
interface UserDetail {
  id: string; samAccountName: string; displayName?: string | null; userPrincipalName?: string | null;
  enabled: boolean; privileged: boolean; privilegeEvidence?: { via?: string[] } | null;
  isServiceAccount: boolean; spnPresent: boolean; spns: string[];
  passwordNeverExpires: boolean; passwordNotRequired: boolean; preauthNotRequired: boolean;
  delegationType: string; delegationTargets: string[];
  riskScore?: number | null; riskFactors?: Array<{ factor: string; points: number }> | null;
  lastLogonAt?: string | null; passwordLastSetAt?: string | null;
  memberships: Array<{ groupRef: string; source: string; confidence: string }>;
  findings: Array<{ id: string; title: string; severity: string; ruleId?: string | null; status: string }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [user, setUser] = useState<UserDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setUser(await apiFetch<UserDetail>(`/ad/users/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the user.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!user) return <p className="text-sm text-slate-400">Loading…</p>;

  const flags: Array<[string, boolean]> = [
    ["Enabled", user.enabled], ["Privileged (evidence-backed)", user.privileged],
    ["Service account", user.isServiceAccount], ["SPN present (inventory)", user.spnPresent],
    ["Password never expires", user.passwordNeverExpires], ["Password not required", user.passwordNotRequired],
    ["Pre-auth not required", user.preauthNotRequired],
  ];

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Directory User" title={user.displayName ?? user.samAccountName} body={`${user.samAccountName} · ${user.userPrincipalName ?? ""}`} />
      <div className="grid md:grid-cols-2 gap-3">
        <Card>
          <h2 className="text-base font-semibold text-slate-100 mb-2">Account flags</h2>
          <ul className="text-sm space-y-1">
            {flags.map(([label, on]) => (
              <li key={label} className="flex justify-between text-slate-300">
                <span>{label}</span><Badge>{on ? "YES" : "no"}</Badge>
              </li>
            ))}
            <li className="flex justify-between text-slate-300"><span>Delegation</span><span>{user.delegationType}{(user.delegationTargets ?? []).length > 0 ? ` → ${user.delegationTargets.join(", ")}` : ""}</span></li>
            <li className="flex justify-between text-slate-300"><span>Last logon</span><span>{user.lastLogonAt ? new Date(user.lastLogonAt).toLocaleString() : "never recorded"}</span></li>
            <li className="flex justify-between text-slate-300"><span>Password last set</span><span>{user.passwordLastSetAt ? new Date(user.passwordLastSetAt).toLocaleString() : "unknown"}</span></li>
          </ul>
          {user.privilegeEvidence?.via && user.privilegeEvidence.via.length > 0 && (
            <p className="text-xs text-slate-400 mt-2">Privilege evidence: {user.privilegeEvidence.via.join("; ")}</p>
          )}
        </Card>
        <Card>
          <h2 className="text-base font-semibold text-slate-100 mb-2">Explainable risk (§77)</h2>
          <p className="text-2xl font-semibold text-slate-100">{user.riskScore ?? "—"}</p>
          {(user.riskFactors ?? []).length === 0 ? (
            <p className="text-sm text-slate-400">No contributing risk factors recorded.</p>
          ) : (
            <ul className="text-sm space-y-1 mt-2">
              {user.riskFactors!.map((f) => (
                <li key={f.factor} className="flex justify-between text-slate-300"><span>{f.factor}</span><span>+{f.points}</span></li>
              ))}
            </ul>
          )}
        </Card>
      </div>
      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Group memberships (evidence-backed, §33)</h2>
        {user.memberships.length === 0 ? <p className="text-sm text-slate-400">No memberships recorded.</p> : (
          <ul className="text-sm space-y-1">
            {user.memberships.map((m, i) => (
              <li key={i} className="text-slate-300 font-mono text-xs">{m.groupRef} <span className="text-slate-500">via {m.source} · confidence {m.confidence}</span></li>
            ))}
          </ul>
        )}
      </Card>
      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Findings</h2>
        {user.findings.length === 0 ? <p className="text-sm text-slate-400">No findings reference this identity.</p> : (
          <ul className="text-sm space-y-1">
            {user.findings.map((f) => (
              <li key={f.id} className="text-slate-300"><Badge>{f.severity}</Badge> {f.title} <span className="text-slate-500">{f.ruleId ?? ""} · {f.status}</span></li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
