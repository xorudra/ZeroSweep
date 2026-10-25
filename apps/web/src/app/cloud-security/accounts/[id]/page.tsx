"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Cloud account page (Prompt 14 §78). Shows identity, posture,
 * scope, inventory snapshots and rollups. Credentials are NEVER
 * displayed (§6/§78): the reference name and a configured flag are
 * the whole credential surface of this page.
 */
interface AccountDetail {
  id: string; provider: string; name: string; externalAccountId: string;
  environment: string; criticality: string; status: string;
  assessmentPolicy: string; credentialReference?: string | null; credentialConfigured: boolean;
  lastInventoryAt?: string | null; lastAssessmentAt?: string | null;
  scopes: Array<{ id: string; includeRegions: string[]; excludeRegions: string[]; includeUnits: string[]; excludeUnits: string[] }>;
  latestSnapshots: Array<{ id: string; regions: string[]; resourceCounts: Record<string, number>; snapshotHash: string; capturedAt?: string }>;
  resourcesByExposure: Record<string, number>;
  identityCount: number; driftCount: number; riskPathCount: number;
}

const PROFILES = ["CLOUD_BASELINE", "CLOUD_COMPREHENSIVE", "CLOUD_INVENTORY", "IAM_REVIEW", "PUBLIC_EXPOSURE_REVIEW", "COMPLIANCE_ASSESSMENT", "IAC_TO_CLOUD_CORRELATION"] as const;
const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [account, setAccount] = useState<AccountDetail | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState<string>("CLOUD_BASELINE");

  const load = useCallback(async () => {
    try {
      setAccount(await apiFetch<AccountDetail>(`/cloud/accounts/${id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  async function validate() {
    setBusy(true);
    try {
      const out = await apiFetch<{ status: string; detail: string }>(`/cloud/accounts/${id}/validate`, { method: "POST", body: "{}" });
      setNotice(`Validation: ${out.status} — ${out.detail}`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Validation failed.");
    } finally { setBusy(false); }
  }

  async function scan() {
    setBusy(true);
    try {
      const out = await apiFetch<{ scanId?: string }>(`/cloud/accounts/${id}/scan`, { method: "POST", body: JSON.stringify({ profile }) });
      setNotice(`Cloud scan started (${out.scanId ?? "queued"}) with profile ${profile}.`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Scan start failed — the account target must be VERIFIED first.");
    } finally { setBusy(false); }
  }

  if (!account && !error) return <div className="p-6 text-sm text-slate-400">Loading…</div>;

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Cloud Account" title={account?.name ?? "Account"} body="Read-only assessment posture (READ_ONLY is the only posture). Credential material is never displayed — the reference name below is the entire credential surface." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {notice && <p className="rounded bg-emerald-950/60 px-3 py-2 text-sm text-emerald-300">{notice}</p>}
      {account && (
        <>
          <Card>
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <Badge>{account.provider}</Badge>
              <span className="font-mono text-slate-300">{account.externalAccountId}</span>
              <Badge>{account.status}</Badge>
              <Badge>{account.assessmentPolicy}</Badge>
              <span className="text-slate-400">{account.environment} · criticality {account.criticality}</span>
              <span className="text-slate-500">{account.credentialConfigured ? `credential reference: ${account.credentialReference}` : "no credential reference — scans report NOT_CONFIGURED"}</span>
            </div>
            <div className="mt-3 flex flex-wrap items-end gap-2">
              <button className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-50" disabled={busy} onClick={() => void validate()}>Validate credential reference</button>
              <label className="flex flex-col gap-1 text-xs text-slate-400">Scan profile
                <select className={inputCls} value={profile} onChange={(e) => setProfile(e.target.value)}>
                  {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </label>
              <button className="rounded bg-cyan-700 px-3 py-1.5 text-sm text-white disabled:opacity-50" disabled={busy} onClick={() => void scan()}>Start assessment</button>
              <span className="ml-auto flex gap-2 text-xs">
                <Link className="rounded-full border border-slate-700 px-3 py-1 text-slate-200" href={`/cloud-security/resources?accountId=${account.id}`}>Resources</Link>
                <Link className="rounded-full border border-slate-700 px-3 py-1 text-slate-200" href={`/cloud-security/iam?accountId=${account.id}`}>IAM</Link>
                <Link className="rounded-full border border-slate-700 px-3 py-1 text-slate-200" href={`/cloud-security/graph?accountId=${account.id}`}>Graph</Link>
              </span>
            </div>
            <p className="mt-2 text-xs text-slate-500">
              {account.lastInventoryAt ? `Last inventory ${new Date(account.lastInventoryAt).toLocaleString()}` : "No inventory yet"} ·
              {account.lastAssessmentAt ? ` last assessment ${new Date(account.lastAssessmentAt).toLocaleString()}` : " never assessed"} ·
              {account.identityCount} identities · {account.driftCount} drift events · {account.riskPathCount} risk paths
            </p>
          </Card>

          <Card>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Exposure rollup</h2>
            <div className="flex flex-wrap gap-2">
              {Object.entries(account.resourcesByExposure).map(([k, v]) => <Badge key={k}>{k}: {v}</Badge>)}
              {Object.keys(account.resourcesByExposure).length === 0 && <p className="text-sm text-slate-500">No resources inventoried yet.</p>}
            </div>
          </Card>

          <Card>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Assessed scope (§5)</h2>
            {account.scopes.length === 0 && <EmptyState title="No scope recorded" body="The whole registered account is in scope; exclusions always win when recorded." />}
            <div className="divide-y divide-slate-800">
              {account.scopes.map((s) => (
                <div key={s.id} className="py-2 text-sm text-slate-300">
                  <p>Regions in scope: {s.includeRegions.length ? s.includeRegions.join(", ") : "all"}{s.excludeRegions.length ? ` · excluded: ${s.excludeRegions.join(", ")}` : ""}</p>
                  <p className="text-slate-500">Units in scope: {s.includeUnits.length ? s.includeUnits.join(", ") : "all"}{s.excludeUnits.length ? ` · excluded: ${s.excludeUnits.join(", ")}` : ""}</p>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Inventory snapshots (§19)</h2>
            {account.latestSnapshots.length === 0 && <p className="text-sm text-slate-500">No snapshots yet — run a CLOUD_INVENTORY or baseline scan.</p>}
            <div className="divide-y divide-slate-800">
              {account.latestSnapshots.map((s) => (
                <div key={s.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                  <span className="font-mono text-xs text-slate-400">{s.snapshotHash.slice(0, 12)}…</span>
                  <span className="text-slate-300">{s.regions.join(", ") || "—"}</span>
                  <span className="text-slate-500">{Object.entries(s.resourceCounts).map(([k, v]) => `${k}: ${v}`).join(" · ")}</span>
                  <span className="ml-auto text-xs text-slate-500">{s.capturedAt ? new Date(s.capturedAt).toLocaleString() : ""}</span>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
