"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Active Directory dashboard (Prompt 15 §90). Identity posture at a
 * glance: forests, domains, domain controllers, identities,
 * privileged accounts, AD CS risk, attack paths and drift.
 * Assessment is DEFENSIVE and READ-ONLY (§83): there is no control
 * anywhere in this product that modifies a directory object,
 * executes an attack path or runs a credential attack — the only
 * actions are register, validate and scan.
 */
interface ForestRow { id: string; name: string; rootDomain: string; status: string; domains: number }
interface DomainRow {
  id: string; dnsName: string; netbiosName?: string | null; environment: string;
  criticality: string; assessmentPolicy: string; status: string;
  users: number; computers: number; attackPaths: number; driftEvents: number;
  lastAssessmentAt?: string | null;
}
interface UsersData { items: Array<{ id: string; privileged: boolean }> }
interface AdcsData { authorities: Array<{ id: string }>; templates: Array<{ id: string; riskClasses: string[] }> }
interface PathsData { items: Array<{ id: string }> }
interface DriftData { items: Array<{ id: string }> }

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const PROFILES = ["AD_BASELINE", "AD_COMPREHENSIVE", "AD_INVENTORY", "ADCS_POSTURE", "SMB_POSTURE", "IDENTITY_GRAPH", "ATTACK_PATH_ANALYSIS"] as const;
const SUBNAV = [
  { href: "/active-directory/attack-paths", label: "Attack Paths" },
  { href: "/active-directory/adcs", label: "AD CS" },
  { href: "/active-directory/smb", label: "SMB" },
  { href: "/active-directory/drift", label: "Drift" },
] as const;

export default function Page() {
  const [forests, setForests] = useState<ForestRow[]>([]);
  const [domains, setDomains] = useState<DomainRow[]>([]);
  const [privilegedCount, setPrivilegedCount] = useState(0);
  const [adcs, setAdcs] = useState<AdcsData>({ authorities: [], templates: [] });
  const [pathCount, setPathCount] = useState(0);
  const [driftCount, setDriftCount] = useState(0);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [profile, setProfile] = useState<string>("AD_BASELINE");
  const [name, setName] = useState("");
  const [dnsName, setDnsName] = useState("");
  const [forestName, setForestName] = useState("");
  const [credRef, setCredRef] = useState("");
  const [dcs, setDcs] = useState("");

  const load = useCallback(async () => {
    try {
      const [fo, dom, users, ad, paths, drift] = await Promise.all([
        apiFetch<{ items: ForestRow[] }>("/ad/forests"),
        apiFetch<{ items: DomainRow[] }>("/ad/domains"),
        apiFetch<UsersData>("/ad/users?privileged=true"),
        apiFetch<AdcsData>("/ad/adcs"),
        apiFetch<PathsData>("/ad/attack-paths"),
        apiFetch<DriftData>("/ad/drift"),
      ]);
      setForests(fo.items ?? []);
      setDomains(dom.items ?? []);
      setPrivilegedCount((users.items ?? []).length);
      setAdcs(ad);
      setPathCount((paths.items ?? []).length);
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
      await apiFetch("/ad/domains", {
        method: "POST",
        body: JSON.stringify({
          name, dnsName,
          ...(forestName ? { forestName } : {}),
          ...(credRef ? { credentialReference: credRef } : {}),
          domainControllers: dcs.split(",").map((h) => h.trim()).filter(Boolean)
            .map((hostname) => ({ hostname, ipAddresses: [] })),
        }),
      });
      setName(""); setDnsName(""); setForestName(""); setCredRef(""); setDcs("");
      setNotice("Domain registered as a verified-target candidate. Validate the credential reference, verify the target registration, then start a scan.");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Domain registration failed — credential references are names only, never values.");
    } finally { setBusy(null); }
  }

  async function validate(id: string) {
    setBusy(id);
    try {
      const out = await apiFetch<{ status: string; detail: string }>(`/ad/domains/${id}/validate`, { method: "POST", body: "{}" });
      setNotice(`Validation: ${out.status} — ${out.detail}`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Validation failed.");
    } finally { setBusy(null); }
  }

  async function scan(id: string) {
    setBusy(id);
    try {
      const out = await apiFetch<{ scanId: string }>(`/ad/domains/${id}/scan`, {
        method: "POST", body: JSON.stringify({ profile }),
      });
      setNotice(`Scan started (${out.scanId}) with profile ${profile}. Collection runs read-only on the DIRECTORY_ANALYSIS worker.`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Scan start failed — the domain target must be VERIFIED first.");
    } finally { setBusy(null); }
  }

  const riskyTemplates = adcs.templates.filter((t) => (t.riskClasses ?? []).length > 0).length;
  const totalUsers = domains.reduce((n, d) => n + d.users, 0);
  const totalComputers = domains.reduce((n, d) => n + d.computers, 0);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Active Directory Security" title="Active Directory" body="Defensive AD security assessment: identity graph, posture, AD CS, attack-path modeling and drift — read-only, fixture/import-based collection on approved internal engagements." />
      <nav className="flex gap-2 flex-wrap">
        {SUBNAV.map((s) => (
          <Link key={s.href} href={s.href} className="rounded bg-slate-900 border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800">{s.label}</Link>
        ))}
      </nav>
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      {state === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state === "ready" && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              ["Forests", forests.length], ["Domains", domains.length],
              ["Users", totalUsers], ["Computers", totalComputers],
              ["Privileged identities", privilegedCount], ["AD CS templates at risk", riskyTemplates],
              ["Attack paths (modeled)", pathCount], ["Drift events", driftCount],
            ].map(([label, value]) => (
              <Card key={label as string}>
                <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
                <p className="text-2xl font-semibold text-slate-100">{value}</p>
              </Card>
            ))}
          </div>

          <Card>
            <h2 className="text-base font-semibold text-slate-100 mb-2">Register a domain</h2>
            <p className="text-sm text-slate-400 mb-3">
              Registration records identity only. The assessment identity is a secret REFERENCE name
              (e.g. vault:prod/ad/assessment-account) — never a password or hash. Domain Admin is never requested (§8).
            </p>
            <div className="flex gap-2 flex-wrap">
              <input className={inputCls} placeholder="Display name" value={name} onChange={(e) => setName(e.target.value)} />
              <input className={inputCls} placeholder="DNS name (corp.example)" value={dnsName} onChange={(e) => setDnsName(e.target.value)} />
              <input className={inputCls} placeholder="Forest name (optional)" value={forestName} onChange={(e) => setForestName(e.target.value)} />
              <input className={inputCls} placeholder="Credential reference (optional)" value={credRef} onChange={(e) => setCredRef(e.target.value)} />
              <input className={inputCls} placeholder="Approved DCs, comma-separated" value={dcs} onChange={(e) => setDcs(e.target.value)} />
              <button className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50" disabled={busy === "register" || !name || !dnsName} onClick={() => void register()}>
                Register domain
              </button>
            </div>
          </Card>

          <Card>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-base font-semibold text-slate-100">Domains</h2>
              <label className="text-sm text-slate-400">
                Profile{" "}
                <select className={inputCls} value={profile} onChange={(e) => setProfile(e.target.value)}>
                  {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </label>
            </div>
            {domains.length === 0 ? (
              <EmptyState title="No domains registered" body="Register a domain above to begin a defensive AD assessment." />
            ) : (
              <table className="w-full text-sm">
                <thead><tr className="text-left text-slate-400">
                  <th className="py-1">Domain</th><th>Environment</th><th>Status</th><th>Users</th><th>Computers</th><th>Paths</th><th>Drift</th><th>Actions</th>
                </tr></thead>
                <tbody>
                  {domains.map((d) => (
                    <tr key={d.id} className="border-t border-slate-800">
                      <td className="py-1.5">
                        <Link className="text-indigo-300 hover:underline" href={`/active-directory/domains/${d.id}`}>{d.dnsName}</Link>
                        <span className="block text-xs text-slate-500">{d.netbiosName ?? ""} · policy {d.assessmentPolicy}</span>
                      </td>
                      <td>{d.environment}</td>
                      <td><Badge>{d.status}</Badge></td>
                      <td>{d.users}</td><td>{d.computers}</td><td>{d.attackPaths}</td><td>{d.driftEvents}</td>
                      <td className="space-x-2">
                        <button className="text-indigo-300 hover:underline disabled:opacity-50" disabled={busy === d.id} onClick={() => void validate(d.id)}>Validate</button>
                        <button className="text-indigo-300 hover:underline disabled:opacity-50" disabled={busy === d.id} onClick={() => void scan(d.id)}>Scan</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
