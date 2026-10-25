"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * AD Certificate Services (Prompt 15 §96): CA inventory and template
 * posture with ESC-class risk classification (§47–§50). This page is
 * configuration review only — no exploitation, enrollment or
 * certificate-request action exists here or anywhere in the
 * product (§120).
 */
interface AdcsData {
  authorities: Array<{ id: string; name: string; dnsName?: string | null; enrollmentServices: unknown; metadata: Record<string, unknown> }>;
  templates: Array<{ id: string; name: string; enabled: boolean; authenticationEkus: string[]; managerApprovalRequired: boolean; authorizedSignaturesRequired: number; riskClasses: string[] }>;
}

export default function Page() {
  const [data, setData] = useState<AdcsData>({ authorities: [], templates: [] });
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<AdcsData>("/ad/adcs"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load AD CS data.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="AD Certificate Services" title="AD Certificate Services" body="CA inventory and certificate-template posture (ESC1–ESC8 configuration classes). Posture analysis only — certificates are never requested, forged or abused." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Certificate authorities</h2>
        {data.authorities.length === 0 ? <EmptyState title="No CAs recorded" body="CAs appear after an ADCS_POSTURE collection." /> : (
          <ul className="text-sm space-y-1">
            {data.authorities.map((ca) => (
              <li key={ca.id} className="text-slate-300">
                {ca.name} <span className="text-slate-500">{ca.dnsName ?? ""}</span>
                {typeof ca.metadata?.editFlags === "string" && (
                  <span className="block text-xs text-slate-400">editFlags: {ca.metadata.editFlags as string}</span>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Certificate templates</h2>
        {data.templates.length === 0 ? <EmptyState title="No templates recorded" body="Templates appear after an ADCS_POSTURE collection." /> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Template</th><th>Enabled</th><th>Manager approval</th><th>Authorized signatures</th><th>Risk classes</th></tr></thead>
            <tbody>
              {data.templates.map((t) => (
                <tr key={t.id} className="border-t border-slate-800">
                  <td className="py-1.5">{t.name}</td>
                  <td>{t.enabled ? "yes" : "no"}</td>
                  <td>{t.managerApprovalRequired ? "required" : "not required"}</td>
                  <td>{t.authorizedSignaturesRequired}</td>
                  <td>
                    {(t.riskClasses ?? []).length === 0
                      ? <span className="text-slate-500">none</span>
                      : t.riskClasses.map((r) => <Badge key={r}>{r}</Badge>)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        <p className="text-xs text-slate-500 mt-2">
          Risk classes describe CONFIGURATION posture from collected data. Confirming any class requires a separate
          authorized validation engagement — this platform never attempts it (§50).
        </p>
      </Card>
    </div>
  );
}
