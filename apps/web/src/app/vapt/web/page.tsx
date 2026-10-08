"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * Web VAPT V2 workspace (Prompt 32 §152): targets, scan wizard entry,
 * recent V2 scans, tool health and coverage summaries. A target here
 * binds a VERIFIED asset to an APPROVED assessment — the page says
 * so, because nothing on it can authorize testing by itself (§6).
 */
interface WebTarget {
  id: string; baseUrl: string; normalizedOrigin: string; environment: string;
  criticality: string; scanProfileKey: string; status: string; createdAt: string;
}
interface Plan {
  id: string; webTargetId: string; profileKey: string; status: string;
  allowedTools: string[]; createdAt: string; scanId?: string | null;
}
interface ToolHealth {
  slug: string; status: string; detail: string; riskClass?: string; recorded: boolean;
}
interface Profile { key: string; name: string; active: boolean; toolSlugs: string[]; notes?: string }

export default function Page() {
  const [targets, setTargets] = useState<WebTarget[]>([]);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [health, setHealth] = useState<ToolHealth[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [form, setForm] = useState({ assetId: "", targetId: "", baseUrl: "", environment: "STAGING" });
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [t, s, h, p] = await Promise.all([
        apiFetch<WebTarget[]>("/vapt/web/targets"),
        apiFetch<Plan[]>("/vapt/scans"),
        apiFetch<ToolHealth[]>("/vapt/tool-health"),
        apiFetch<Profile[]>("/vapt/profiles"),
      ]);
      setTargets(t); setPlans(s); setHealth(h); setProfiles(p);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    setBusy(true); setNotice("");
    try {
      await apiFetch("/vapt/web/targets", { method: "POST", body: JSON.stringify(form) });
      setNotice("Target created — bound to the APPROVED assessment on the parent target.");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Create failed.");
    } finally { setBusy(false); }
  };

  const unavailable = health.filter((h) => h.status === "UNAVAILABLE").length;
  return (
    <main>
      <PageHeader eyebrow="Web & API VAPT V2" title="Web Application VAPT" />
      <p style={{ color: "var(--muted, #666)", maxWidth: 780 }}>
        Governed web testing over the platform&apos;s canonical targets. Active scanning requires a
        VERIFIED target and an APPROVED assessment; HIGH-risk modules (SQLmap, Commix, SSTImap) are
        detection-only and pass a separate approval gate. Credentials are secret references — never values.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {notice ? <p>{notice}</p> : null}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12 }}>
        <StatCard label="Web Targets" value={targets.length} />
        <StatCard label="V2 Plans" value={plans.length} />
        <StatCard label="Blocked Plans" value={plans.filter((p) => p.status === "BLOCKED").length} />
        <StatCard label="Tools Unavailable" value={unavailable} />
      </div>

      <Card title="New web target">
        <div style={{ display: "grid", gap: 8, maxWidth: 560 }}>
          <label>Asset ID <input value={form.assetId} onChange={(e) => setForm({ ...form, assetId: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Parent target ID (must be VERIFIED, with an APPROVED assessment)
            <input value={form.targetId} onChange={(e) => setForm({ ...form, targetId: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Base URL <input value={form.baseUrl} placeholder="https://staging.example.com" onChange={(e) => setForm({ ...form, baseUrl: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Environment
            <select value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })}>
              {["PRODUCTION", "STAGING", "DEVELOPMENT", "TEST", "UNKNOWN"].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
          <button disabled={busy} onClick={() => void create()}>Create target</button>
        </div>
      </Card>

      <Card title="Targets">
        {targets.length === 0 ? <EmptyState title="No web targets yet." body="Create one from a verified asset above." /> : (
          <ul>
            {targets.map((t) => (
              <li key={t.id}>
                <Link href={`/vapt/web/targets/${t.id}`}>{t.normalizedOrigin}</Link>{" "}
                — {t.environment} · {t.criticality} · profile {t.scanProfileKey} · {t.status}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Recent V2 scan plans">
        {plans.length === 0 ? <EmptyState title="No plans yet." body="Plans are generated from a target's detail page — stages, budget and blocked modules are shown before anything runs." /> : (
          <ul>
            {plans.slice(0, 10).map((p) => (
              <li key={p.id}>
                profile {p.profileKey} · {p.status} · tools: {p.allowedTools.join(", ") || "—"}
                {p.scanId ? <> · <Link href={`/vapt/scans/${p.scanId}`}>scan detail</Link></> : null}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Tool health (§146)">
        <ul>
          {health.map((h) => (
            <li key={h.slug}><strong>{h.slug}</strong> — {h.status}{h.riskClass ? ` · risk ${h.riskClass}` : ""} · {h.detail}</li>
          ))}
        </ul>
        <p style={{ color: "var(--muted, #666)" }}>Unavailable tools are reported honestly; a scan with gaps completes as COMPLETED_WITH_GAPS, never as silently clean.</p>
      </Card>

      <Card title="Profiles (§122)">
        <ul>
          {profiles.map((p) => (
            <li key={p.key}><strong>{p.key}</strong> — {p.name} · {p.active ? "active" : "passive"} · {p.toolSlugs.join(", ")}{p.notes ? ` · ${p.notes}` : ""}</li>
          ))}
        </ul>
      </Card>
    </main>
  );
}
