"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface IntegrationRow {
  id: string; name: string; type: string; status: string; enabled: boolean;
  capabilities: string[]; secretConfigured: boolean; secretRotatedAt?: string | null;
  credentialType?: string | null; lastSyncAt?: string | null; lastHealthCheckAt?: string | null;
  lastErrorCategory?: string | null;
}

const TYPES = ["GITHUB", "GITLAB", "BITBUCKET", "JIRA", "SLACK", "MICROSOFT_TEAMS", "SIEM", "GENERIC_WEBHOOK"];

/**
 * Integration settings (Prompt 24 §93): every enterprise integration
 * with status, capabilities, last sync and health. Credentials are
 * secret REFERENCES — this page shows whether one is configured, its
 * type and when it was last rotated; a secret value can never be
 * entered or displayed here (§7/§8).
 */
export default function Page() {
  const [rows, setRows] = useState<IntegrationRow[] | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [form, setForm] = useState({ type: "GITHUB", name: "", secretReference: "" });

  const load = useCallback(() => {
    apiFetch<IntegrationRow[]>("/integrations").then(setRows).catch(() => setRows([]));
  }, []);
  useEffect(() => { load(); }, [load]);

  const create = async () => {
    try {
      await apiFetch("/integrations", {
        method: "POST",
        body: JSON.stringify({
          type: form.type, name: form.name || form.type,
          configuration: {},
          ...(form.secretReference ? { secretReference: form.secretReference } : {}),
        }),
      });
      setMessage("Integration created (PENDING until a successful test connection).");
      setForm({ type: "GITHUB", name: "", secretReference: "" });
      load();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Create failed");
    }
  };

  const act = async (id: string, action: "test" | "sync") => {
    try {
      const result = await apiFetch<Record<string, unknown>>(`/integrations/${id}/${action}`, {
        method: "POST", body: JSON.stringify({}),
      });
      setMessage(JSON.stringify(result).slice(0, 300));
      load();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Action failed");
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Settings · Integrations"
        title="Enterprise Integrations"
        body="Source control, ticketing, messaging, SIEM and webhooks. Provider transports are wired per deployment; an unconfigured integration reports NOT_CONFIGURED honestly rather than pretending to be connected."
      />
      {message ? <p className="mb-4 text-sm text-sky-300">{message}</p> : null}
      <Card>
        <h2 className="text-base font-semibold text-slate-100">Configured integrations</h2>
        {rows === null ? <p className="mt-2 text-sm text-slate-400">Loading…</p> : null}
        {rows && rows.length === 0 ? (
          <EmptyState title="No integrations yet" body="Create one below. Scanning integrations stay DISABLED until configured and tested." />
        ) : null}
        {rows && rows.length > 0 ? (
          <table className="mt-3 w-full text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="px-2 py-1">Name</th><th className="px-2 py-1">Type</th><th className="px-2 py-1">Status</th>
                <th className="px-2 py-1">Credential</th><th className="px-2 py-1">Last sync</th><th className="px-2 py-1">Health</th><th className="px-2 py-1">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-t border-slate-800">
                  <td className="px-2 py-2 text-slate-200">{r.name}</td>
                  <td className="px-2 py-2 text-slate-300">{r.type}</td>
                  <td className="px-2 py-2">
                    <Badge tone={r.status === "CONNECTED" ? "ok" : r.status === "AUTHENTICATION_FAILED" ? "critical" : r.status === "DEGRADED" ? "high" : "neutral"}>{r.status}</Badge>
                  </td>
                  <td className="px-2 py-2 text-slate-300">
                    {r.secretConfigured ? `Configured${r.credentialType ? ` (${r.credentialType})` : ""}${r.secretRotatedAt ? ` · rotated ${new Date(r.secretRotatedAt).toLocaleDateString()}` : ""}` : "Not configured"}
                  </td>
                  <td className="px-2 py-2 text-slate-300">{r.lastSyncAt ? new Date(r.lastSyncAt).toLocaleString() : "—"}</td>
                  <td className="px-2 py-2 text-slate-300">{r.lastErrorCategory ?? "—"}</td>
                  <td className="px-2 py-2">
                    <button type="button" onClick={() => act(r.id, "test")} className="mr-2 rounded border border-slate-600 px-2 py-1 text-xs text-slate-200">Test</button>
                    <button type="button" onClick={() => act(r.id, "sync")} className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-200">Sync</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </Card>
      <Card>
        <h2 className="text-base font-semibold text-slate-100">Add integration</h2>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <label className="text-sm text-slate-400">
            Type
            <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })} className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-2 text-slate-100">
              {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <label className="text-sm text-slate-400">
            Name
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-2 text-slate-100" placeholder="e.g. GitHub (Rudra)" />
          </label>
          <label className="text-sm text-slate-400 md:col-span-2">
            Secret reference (never the secret itself)
            <input value={form.secretReference} onChange={(e) => setForm({ ...form, secretReference: e.target.value })} className="mt-1 w-full rounded border border-slate-700 bg-slate-900 px-2 py-2 text-slate-100" placeholder="env:GITHUB_WEBHOOK_SECRET" />
          </label>
        </div>
        <button type="button" onClick={create} className="mt-4 rounded bg-sky-600 px-4 py-2 text-sm font-medium text-white">Create integration</button>
        <p className="mt-2 text-xs text-slate-500">Provider-specific non-secret configuration (app IDs, project keys, base URLs) is managed through the API; secret values live only in the deployment secret store.</p>
      </Card>
    </>
  );
}
