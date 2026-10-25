"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Cloud security dashboard (Prompt 14 §77). Multi-cloud posture at a
 * glance: registered accounts (AWS/Azure/GCP), public exposure, IAM
 * risk, drift and compliance rollups. Assessment is READ-ONLY (§7):
 * there is no button anywhere in this product that changes a cloud
 * resource — the only actions are register, validate and scan.
 */
interface AccountRow {
  id: string; provider: string; name: string; externalAccountId: string;
  environment: string; status: string; credentialConfigured: boolean;
  credentialReference?: string | null; resources: number; identities: number;
  publicResources: number; lastAssessmentAt?: string | null;
}
interface ExposureData { resources: Array<{ id: string }>; exposureFindings: Array<{ id: string; severity: string }> }
interface DriftData { items: Array<{ id: string }> }

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const PROFILES = ["CLOUD_BASELINE", "CLOUD_COMPREHENSIVE", "CLOUD_INVENTORY", "IAM_REVIEW", "PUBLIC_EXPOSURE_REVIEW", "COMPLIANCE_ASSESSMENT", "IAC_TO_CLOUD_CORRELATION"] as const;
const SUBNAV = [
  { href: "/cloud-security/resources", label: "Resources" },
  { href: "/cloud-security/iam", label: "IAM" },
  { href: "/cloud-security/exposure", label: "Network Exposure" },
  { href: "/cloud-security/storage", label: "Storage" },
  { href: "/cloud-security/graph", label: "Cloud Graph" },
  { href: "/compliance", label: "Compliance" },
] as const;

export default function Page() {
  const [accounts, setAccounts] = useState<AccountRow[]>([]);
  const [exposure, setExposure] = useState<ExposureData>({ resources: [], exposureFindings: [] });
  const [driftCount, setDriftCount] = useState(0);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [profile, setProfile] = useState<string>("CLOUD_BASELINE");
  const [name, setName] = useState("");
  const [provider, setProvider] = useState("AWS");
  const [externalId, setExternalId] = useState("");
  const [credRef, setCredRef] = useState("");
  const [regions, setRegions] = useState("");

  const load = useCallback(async () => {
    try {
      const [acc, exp, drift] = await Promise.all([
        apiFetch<{ items: AccountRow[] }>("/cloud/accounts"),
        apiFetch<ExposureData>("/cloud/exposure"),
        apiFetch<DriftData>("/cloud/drift"),
      ]);
      setAccounts(acc.items ?? []);
      setExposure(exp);
      setDriftCount((drift.items ?? []).length);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function register() {
    setBusy("register");
    try {
      await apiFetch("/cloud/accounts", {
        method: "POST",
        body: JSON.stringify({
          name, provider, externalAccountId: externalId,
          ...(credRef ? { credentialReference: credRef } : {}),
          scope: {
            includeRegions: regions.split(",").map((r) => r.trim()).filter(Boolean),
            excludeRegions: [], includeUnits: [], excludeUnits: [], includeResources: [], excludeResources: [],
          },
        }),
      });
      setName(""); setExternalId(""); setCredRef(""); setRegions("");
      setNotice("Account registered as a verified-target candidate. Validate the credential reference, verify the target registration, then start a scan.");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Account registration failed — credential references are names only, never values.");
    } finally { setBusy(null); }
  }

  async function validate(id: string) {
    setBusy(id);
    try {
      const out = await apiFetch<{ status: string; detail: string }>(`/cloud/accounts/${id}/validate`, { method: "POST", body: "{}" });
      setNotice(`Validation: ${out.status} — ${out.detail}`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Validation failed.");
    } finally { setBusy(null); }
  }

  async function scan(id: string) {
    setBusy(id);
    try {
      const out = await apiFetch<{ scanId?: string }>(`/cloud/accounts/${id}/scan`, { method: "POST", body: JSON.stringify({ profile }) });
      setNotice(`Cloud scan started (${out.scanId ?? "queued"}) with profile ${profile}.`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Scan start failed — the account target must be VERIFIED first.");
    } finally { setBusy(null); }
  }

  const byProvider = (p: string) => accounts.filter((a) => a.provider === p);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Multi-Cloud Security" title="Cloud Security" body="Read-only security assessment for AWS, Azure and GCP (Prompt 14). ZeroSweep never creates, modifies or deletes a cloud resource and never stores a credential value — accounts are referenced by secret-manager reference names only." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {notice && <p className="rounded bg-emerald-950/60 px-3 py-2 text-sm text-emerald-300">{notice}</p>}

      <div className="flex flex-wrap gap-2">
        {SUBNAV.map((s) => <Link key={s.href} href={s.href} className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-200 hover:bg-slate-800">{s.label}</Link>)}
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        {(["AWS", "AZURE", "GCP"] as const).map((p) => (
          <Card key={p}>
            <p className="text-xs uppercase tracking-wide text-slate-400">{p} accounts</p>
            <p className="mt-1 text-2xl font-bold text-slate-50">{byProvider(p).length}</p>
            <p className="text-xs text-slate-500">{byProvider(p).reduce((n, a) => n + a.resources, 0)} resources inventoried</p>
          </Card>
        ))}
        <Card>
          <p className="text-xs uppercase tracking-wide text-slate-400">Public exposure</p>
          <p className="mt-1 text-2xl font-bold text-slate-50">{exposure.resources.length}</p>
          <p className="text-xs text-slate-500">{exposure.exposureFindings.length} exposure findings · {driftCount} drift events</p>
        </Card>
      </div>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Register cloud account (reference only)</h2>
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-xs text-slate-400">Account name
            <input className={inputCls} placeholder="prod-aws" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Provider
            <select className={inputCls} value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="AWS">AWS</option><option value="AZURE">Azure</option><option value="GCP">GCP</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Account / subscription / project id
            <input className={`${inputCls} w-64`} placeholder="123456789012" value={externalId} onChange={(e) => setExternalId(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Credential reference (name only)
            <input className={`${inputCls} w-64`} placeholder="vault:prod/aws/assessment-role" value={credRef} onChange={(e) => setCredRef(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Regions in scope (comma separated)
            <input className={inputCls} placeholder="us-east-1, eu-west-1" value={regions} onChange={(e) => setRegions(e.target.value)} />
          </label>
          <button className="rounded bg-cyan-700 px-3 py-1.5 text-sm text-white disabled:opacity-50" disabled={busy === "register" || !name || !externalId} onClick={() => void register()}>Register</button>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Scan profile
            <select className={inputCls} value={profile} onChange={(e) => setProfile(e.target.value)}>
              {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
        </div>
        <p className="mt-2 text-xs text-slate-500">The credential itself never enters ZeroSweep: the worker resolves the reference under a job-scoped lease and requests read-only access only. Example: Rudra registers <span className="font-mono">prod-aws</span> with reference <span className="font-mono">vault:prod/aws/assessment-role</span>.</p>
      </Card>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Accounts</h2>
        {state === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
        {state === "ready" && accounts.length === 0 && <EmptyState title="No cloud accounts registered" body="Register an account above — unconfigured accounts honestly report NOT_CONFIGURED and their scans do not fabricate inventory." />}
        <div className="divide-y divide-slate-800">
          {accounts.map((a) => (
            <div key={a.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Link className="text-cyan-300 hover:underline" href={`/cloud-security/accounts/${a.id}`}>{a.name}</Link>
              <Badge>{a.provider}</Badge>
              <span className="font-mono text-slate-400">{a.externalAccountId}</span>
              <Badge>{a.status}</Badge>
              <span className="text-slate-400">{a.resources} resources · {a.identities} identities · {a.publicResources} public</span>
              <span className="text-slate-500">{a.credentialConfigured ? `credential: ${a.credentialReference} (reference)` : "no credential reference"}</span>
              <span className="ml-auto flex gap-2">
                <button className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 disabled:opacity-50" disabled={busy === a.id} onClick={() => void validate(a.id)}>Validate</button>
                <button className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 disabled:opacity-50" disabled={busy === a.id} onClick={() => void scan(a.id)}>Assess ({profile})</button>
              </span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
