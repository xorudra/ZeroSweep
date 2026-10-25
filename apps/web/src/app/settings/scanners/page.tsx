"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Admin → Scanner Instances (Prompt 8 §54/§55). Owner/Admin register the
 * ZAP / Burp / Caido deployments ZeroSweep may talk to. The form accepts an
 * opaque endpoint REFERENCE NAME (resolved from server configuration) and
 * a credential REFERENCE NAME — never a URL and never a secret value, so
 * this page cannot become an SSRF or credential-leak surface (§17/§20).
 */

interface InstanceView {
  id: string; toolSlug: string; name: string; endpointReference: string;
  deploymentType: string; credentialReference?: string | null;
  declaredCapabilities?: string[]; detectedCapabilities?: string[];
  config?: { profiles?: Record<string, string>; feedStatus?: string };
  feedStatus?: string | null;
  healthStatus: string; version?: string | null; licenseState?: string | null;
  lastHealthCheckAt?: string | null; lastHealthDetail?: string | null; enabled: boolean;
}
interface SessionProfile {
  id: string; name: string; type: string; credentialReference?: string | null;
  validation?: { authenticatedUrl?: string; expectedStatus?: number } | null;
  authProfiles?: Array<{ id: string; mode: string }>;
}
interface Approval {
  id: string; assessmentId: string; capability: string; status: string;
  evaluatedState?: string; approvedBy: string; expiresAt: string; createdAt: string;
}

const PRODUCTS = [
  { slug: "owasp-zap", name: "OWASP ZAP", capabilities: ["PROXY", "PASSIVE_ANALYSIS", "CONTEXT_MANAGEMENT", "ENDPOINT_IMPORT", "ISSUE_IMPORT", "WEB_CRAWLING", "ENDPOINT_DISCOVERY", "VULNERABILITY_SCANNING", "ACTIVE_WEB_SCANNING"] },
  { slug: "burp-suite-professional", name: "Burp Suite Professional", capabilities: ["PROXY", "PASSIVE_ANALYSIS", "SITE_MAP_IMPORT", "ISSUE_IMPORT", "WEB_CRAWLING", "ACTIVE_WEB_SCANNING"] },
  { slug: "caido", name: "Caido", capabilities: ["PROXY", "TRAFFIC_ANALYSIS", "ENDPOINT_DISCOVERY", "REQUEST_COLLECTION", "ISSUE_IMPORT"] },
  // Prompt 11 §3/§10: vulnerability scanners. Nessus is COMMERCIAL /
  // ADMIN_PROVIDED / LICENSE_REQUIRED — registering an instance never
  // implies a license exists; health reports what the deployment says.
  { slug: "greenbone-openvas", name: "Greenbone / OpenVAS", capabilities: ["VULNERABILITY_SCANNING", "NETWORK_VULNERABILITY_ASSESSMENT", "SCAN_RESULT_IMPORT", "VULNERABILITY_DETECTION"] },
  { slug: "nessus-professional", name: "Nessus Professional (commercial, admin-provided)", capabilities: ["VULNERABILITY_SCANNING", "NETWORK_VULNERABILITY_ASSESSMENT", "SCAN_RESULT_IMPORT", "VULNERABILITY_DETECTION"] },
];

const inputCls = "w-full rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-100 outline-none ring-slate-700 focus:ring-1";
const labelCls = "block text-xs uppercase tracking-wide text-slate-500";

export default function ScannerSettingsPage() {
  const [instances, setInstances] = useState<InstanceView[] | null>(null);
  const [profiles, setProfiles] = useState<SessionProfile[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const [form, setForm] = useState({ name: "", toolSlug: PRODUCTS[0]!.slug, endpointReference: "", deploymentType: "MANAGED_DAEMON", credentialReference: "" });
  const [profileForm, setProfileForm] = useState({ name: "", type: "AUTHENTICATED", credentialReference: "", authenticatedUrl: "", expectedStatus: "200" });
  const [approvalForm, setApprovalForm] = useState({ assessmentId: "", expiresAt: "" });

  const load = useCallback(async () => {
    try {
      const [inst, profs, appr] = await Promise.all([
        apiFetch<InstanceView[]>("/scanners/instances"),
        apiFetch<SessionProfile[]>("/scanners/session-profiles").catch(() => []),
        apiFetch<Approval[]>("/scanners/approvals").catch(() => []),
      ]);
      setInstances(inst); setProfiles(profs); setApprovals(appr);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load scanner settings (Owner/Admin role required).");
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key); setError(null); setNotice(null);
    try { await fn(); setNotice(ok); await load(); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Request failed"); }
    finally { setBusy(null); }
  };

  const product = PRODUCTS.find((p) => p.slug === form.toolSlug) ?? PRODUCTS[0]!;

  return (
    <>
      <PageHeader eyebrow="Settings / Scanners" title="Scanner instances"
        body="Register the OWASP ZAP, Burp Suite Professional and Caido deployments ZeroSweep may use. Instances are referenced by NAME: the real endpoint is resolved from server configuration and credentials live in the vault — neither is ever entered or shown here." />
      {error ? <Card><p className="text-sm text-red-300">{error}</p></Card> : null}
      {notice ? <Card><p className="text-sm text-emerald-300">{notice}</p></Card> : null}

      <div className="space-y-6">
        <Card title="Registered instances">
          {instances === null ? <p className="text-sm text-slate-400">Loading…</p> : instances.length === 0 ? (
            <EmptyState title="No scanner instances" body="Nothing is configured yet — every connector honestly reports NOT_CONFIGURED and passive analysis is skipped in scans. Register the first instance below." />
          ) : (
            <div className="space-y-3">
              {instances.map((inst) => (
                <div key={inst.id} className="rounded-lg border border-slate-800 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-slate-100">{inst.name}</span>
                    <Badge>{inst.toolSlug}</Badge>
                    <Badge>{inst.deploymentType}</Badge>
                    <span className="text-sm text-slate-300">{inst.healthStatus}</span>
                    {!inst.enabled ? <Badge>DISABLED</Badge> : null}
                    <span className="ml-auto flex gap-2">
                      <button disabled={busy !== null} onClick={() => void act(`health-${inst.id}`, () => apiFetch(`/scanners/instances/${inst.id}/health-check`, { method: "POST" }), "Health check recorded")} className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 disabled:opacity-50">Health check</button>
                      <button disabled={busy !== null} onClick={() => void act(`toggle-${inst.id}`, () => apiFetch(`/scanners/instances/${inst.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !inst.enabled }) }), inst.enabled ? "Instance disabled" : "Instance enabled")} className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 disabled:opacity-50">{inst.enabled ? "Disable" : "Enable"}</button>
                      <button disabled={busy !== null} onClick={() => void act(`del-${inst.id}`, () => apiFetch(`/scanners/instances/${inst.id}`, { method: "DELETE" }), "Instance removed")} className="rounded bg-red-900 px-2 py-1 text-xs text-red-100 disabled:opacity-50">Delete</button>
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    Endpoint reference: {inst.endpointReference} · Credential: {inst.credentialReference ? `reference “${inst.credentialReference}”` : "none"}
                    {inst.version ? ` · Version ${inst.version}` : ""}{inst.licenseState ? ` · License: ${inst.licenseState}` : ""}
                    {(inst.toolSlug === "greenbone-openvas" || inst.toolSlug === "nessus-professional") ? (
                      <span className="block text-xs text-slate-500">
                        Feed: {inst.feedStatus ?? inst.config?.feedStatus ?? "not reported"} · Logical profiles: {inst.config?.profiles ? Object.entries(inst.config.profiles).map(([k, v]) => `${k} → ${v}`).join(", ") : "none mapped — an administrator maps logical profiles to approved scanner policies (§7/§12); users never submit raw policy ids"}
                      </span>
                    ) : null}
                    {inst.lastHealthCheckAt ? ` · Last check ${new Date(inst.lastHealthCheckAt).toLocaleString()}` : " · Never health-checked"}
                  </p>
                  {inst.lastHealthDetail ? <p className="mt-1 text-xs text-slate-500">{inst.lastHealthDetail}</p> : null}
                  <p className="mt-1 text-xs text-slate-500">Detected capabilities: {(inst.detectedCapabilities ?? []).join(", ") || "— (run a health check)"}</p>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Register an instance (Owner/Admin)">
          <form className="grid gap-3 md:grid-cols-2" onSubmit={(e) => {
            e.preventDefault();
            void act("create", () => apiFetch("/scanners/instances", {
              method: "POST",
              body: JSON.stringify({
                name: form.name, toolSlug: form.toolSlug, endpointReference: form.endpointReference,
                deploymentType: form.deploymentType,
                ...(form.credentialReference ? { credentialReference: form.credentialReference } : {}),
                declaredCapabilities: product.capabilities,
              }),
            }), "Instance registered — run a health check to probe it");
          }}>
            <label className={labelCls}>Display name
              <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className={inputCls} placeholder="e.g. ZAP daemon (CI)" />
            </label>
            <label className={labelCls}>Product
              <select value={form.toolSlug} onChange={(e) => setForm({ ...form, toolSlug: e.target.value })} className={inputCls}>
                {PRODUCTS.map((p) => <option key={p.slug} value={p.slug}>{p.name}</option>)}
              </select>
            </label>
            <label className={labelCls}>Endpoint reference (name, never a URL)
              <input required value={form.endpointReference} onChange={(e) => setForm({ ...form, endpointReference: e.target.value })} className={inputCls} placeholder="ZAP_DAEMON_PROD" pattern="[A-Z][A-Z0-9_:\-]{2,63}" />
            </label>
            <label className={labelCls}>Deployment type
              <select value={form.deploymentType} onChange={(e) => setForm({ ...form, deploymentType: e.target.value })} className={inputCls}>
                <option value="MANAGED_DAEMON">Managed daemon</option>
                <option value="ADMIN_PROVIDED">Admin provided (e.g. Burp)</option>
                <option value="IMPORT_ONLY">Import only</option>
              </select>
            </label>
            <label className={labelCls}>Credential reference (optional)
              <input value={form.credentialReference} onChange={(e) => setForm({ ...form, credentialReference: e.target.value })} className={inputCls} placeholder="ZAP_API_KEY_PROD" />
            </label>
            <div className="flex items-end">
              <button disabled={busy !== null} className="rounded bg-sky-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">Register instance</button>
            </div>
            <p className="text-xs text-slate-500 md:col-span-2">
              The reference must exist in the server&apos;s scanner-endpoint configuration (DSRCLONE_SCANNER_ENDPOINTS)
              and the credential reference in the worker environment. URLs, hostnames and IPs are rejected here by
              design — that is what keeps scanner registration SSRF-safe. Burp Suite is commercial: register the
              bridge inside your licensed Burp environment (see docs/tools/proxy/burp.md).
            </p>
          </form>
        </Card>

        <Card title="Session profiles">
          <p className="mb-3 text-sm text-slate-400">
            Reusable authenticated-scan sessions. A profile stores metadata and a credential reference only — cookie
            and header NAMES, never values. Session validity is proven against a known authenticated URL at scan
            time; an expired session marks the scan partial instead of retrying credentials.
          </p>
          {profiles.length === 0 ? <p className="text-sm text-slate-500">No session profiles yet.</p> : (
            <ul className="mb-3 space-y-1 text-sm text-slate-300">
              {profiles.map((p) => (
                <li key={p.id}>{p.name} · {p.type} · credential {p.credentialReference ? `reference “${p.credentialReference}”` : "none"}
                  {p.validation?.authenticatedUrl ? ` · validates at ${p.validation.authenticatedUrl}` : ""}</li>
              ))}
            </ul>
          )}
          <form className="grid gap-3 md:grid-cols-2" onSubmit={(e) => {
            e.preventDefault();
            void act("profile", () => apiFetch("/scanners/session-profiles", {
              method: "POST",
              body: JSON.stringify({
                name: profileForm.name, type: profileForm.type,
                ...(profileForm.credentialReference ? { credentialReference: profileForm.credentialReference } : {}),
                ...(profileForm.authenticatedUrl ? { validation: { authenticatedUrl: profileForm.authenticatedUrl, expectedStatus: Number(profileForm.expectedStatus) || 200 } } : {}),
              }),
            }), "Session profile created");
          }}>
            <label className={labelCls}>Name<input required value={profileForm.name} onChange={(e) => setProfileForm({ ...profileForm, name: e.target.value })} className={inputCls} /></label>
            <label className={labelCls}>Type
              <select value={profileForm.type} onChange={(e) => setProfileForm({ ...profileForm, type: e.target.value })} className={inputCls}>
                <option value="ANONYMOUS">Anonymous</option>
                <option value="AUTHENTICATED">Authenticated</option>
                <option value="API_AUTHENTICATED">API authenticated</option>
              </select>
            </label>
            <label className={labelCls}>Credential reference<input value={profileForm.credentialReference} onChange={(e) => setProfileForm({ ...profileForm, credentialReference: e.target.value })} className={inputCls} placeholder="APP_SESSION_PROD" /></label>
            <label className={labelCls}>Authenticated URL (session validation)<input value={profileForm.authenticatedUrl} onChange={(e) => setProfileForm({ ...profileForm, authenticatedUrl: e.target.value })} className={inputCls} placeholder="https://example.com/account" /></label>
            <div className="flex items-end"><button disabled={busy !== null} className="rounded bg-sky-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">Create profile</button></div>
          </form>
        </Card>

        <Card title="Active-scan approvals">
          <p className="mb-3 text-sm text-slate-400">
            Active scanning (ACTIVE_WEB_SCANNING) is intrusive and disabled by default. An approval is a human,
            expiring decision bound to the assessment&apos;s scope snapshot — change the scope and the approval is
            invalidated. Granting requires a verified target and an approved assessment.
          </p>
          {approvals.length === 0 ? <p className="text-sm text-slate-500">No approvals recorded.</p> : (
            <ul className="mb-3 space-y-1 text-sm text-slate-300">
              {approvals.map((a) => (
                <li key={a.id} className="flex flex-wrap items-center gap-2">
                  <span>{a.capability} · assessment {a.assessmentId.slice(0, 8)}… · <span className="text-slate-100">{a.evaluatedState ?? a.status}</span> · expires {new Date(a.expiresAt).toLocaleString()}</span>
                  {a.status === "ACTIVE" ? (
                    <button disabled={busy !== null} onClick={() => void act(`revoke-${a.id}`, () => apiFetch(`/scanners/approvals/${a.id}/revoke`, { method: "POST" }), "Approval revoked")} className="rounded bg-red-900 px-2 py-0.5 text-xs text-red-100 disabled:opacity-50">Revoke</button>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
          <form className="grid gap-3 md:grid-cols-3" onSubmit={(e) => {
            e.preventDefault();
            void act("approve", () => apiFetch("/scanners/approvals", {
              method: "POST",
              body: JSON.stringify({ assessmentId: approvalForm.assessmentId, capability: "ACTIVE_WEB_SCANNING", ...(approvalForm.expiresAt ? { expiresAt: new Date(approvalForm.expiresAt).toISOString() } : {}) }),
            }), "Approval granted");
          }}>
            <label className={labelCls}>Assessment ID<input required value={approvalForm.assessmentId} onChange={(e) => setApprovalForm({ ...approvalForm, assessmentId: e.target.value })} className={inputCls} placeholder="uuid" /></label>
            <label className={labelCls}>Expires at (optional)<input type="datetime-local" value={approvalForm.expiresAt} onChange={(e) => setApprovalForm({ ...approvalForm, expiresAt: e.target.value })} className={inputCls} /></label>
            <div className="flex items-end"><button disabled={busy !== null} className="rounded bg-amber-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">Grant approval</button></div>
          </form>
        </Card>
      </div>
    </>
  );
}
