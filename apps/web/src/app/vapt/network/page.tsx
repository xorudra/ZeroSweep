"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * Network VAPT V2 dashboard (Prompt 33 §113): authorized networks,
 * active hosts, open services, sensitive services, critical
 * vulnerabilities, KEV, internet exposure, recent drift, scan status
 * and tool health — all from recorded platform data. Nothing here
 * authorizes a scan by itself: targets bind a VERIFIED parent target
 * to an APPROVED assessment (§7), and Masscan/NSE brute categories
 * stay structurally blocked (§27/§37).
 */
interface NetTarget {
  id: string; targetType: string; targetValue: string; environment: string;
  criticality: string; scanProfileId: string; status: string; createdAt: string;
}
interface Plan {
  id: string; targetId: string; profile: string; status: string; tools: unknown; scanId?: string | null; createdAt: string;
}
interface HostRow {
  id: string; host: string; ip?: string | null; zone: string; openServices: number; internetExposedSensitive: number;
}
interface ToolHealth { slug: string; name: string; status: string; executionMode: string; notes: string }
interface Drift { id: string; host: string; kind: string; detail: string; riskSignal: string; createdAt: string }

const PROFILES = [
  { key: "NETWORK_DISCOVERY", note: "Host/port/service inventory only" },
  { key: "NETWORK_SAFE", note: "Production default — governed SAFE checks, protocol + TLS analysis" },
  { key: "NETWORK_STANDARD", note: "Adds L2 discovery (attached workers) + small governed UDP set" },
  { key: "NETWORK_VULNERABILITY", note: "Adds Greenbone/Nessus under logical profiles; scanner gaps = PARTIAL, never clean" },
  { key: "TLS_NETWORK", note: "TLS posture only" },
  { key: "TARGETED_SERVICE_VERIFICATION", note: "Minimal-scope fix verification feeding Prompt 31 remediation" },
];

export default function Page() {
  const [targets, setTargets] = useState<NetTarget[]>([]);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [health, setHealth] = useState<ToolHealth[]>([]);
  const [drift, setDrift] = useState<Drift[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [form, setForm] = useState({ assetId: "", targetId: "", targetValue: "", targetType: "CIDR", environment: "PRODUCTION", internalEngagementApproved: false });
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [t, s, h, th, d] = await Promise.all([
        apiFetch<NetTarget[]>("/vapt/network/targets"),
        apiFetch<Plan[]>("/vapt/network/scans"),
        apiFetch<HostRow[]>("/vapt/network/hosts"),
        apiFetch<ToolHealth[]>("/vapt/network/tool-health"),
        apiFetch<Drift[]>("/vapt/network/drift"),
      ]);
      setTargets(t); setPlans(s); setHosts(h); setHealth(th); setDrift(d);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    setBusy(true); setNotice("");
    try {
      await apiFetch("/vapt/network/targets", { method: "POST", body: JSON.stringify(form) });
      setNotice("Network target created — bound to the APPROVED assessment on the parent target.");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Create failed.");
    } finally { setBusy(false); }
  };

  const openServices = hosts.reduce((n, h) => n + h.openServices, 0);
  const sensitiveExposed = hosts.reduce((n, h) => n + h.internetExposedSensitive, 0);
  return (
    <main>
      <PageHeader eyebrow="Network VAPT V2" title="Network VAPT" />
      <p style={{ color: "var(--muted, #666)", maxWidth: 820 }}>
        Governed network testing over the Prompt 10 engine. Active operations require a VERIFIED target
        and an APPROVED assessment; discovered hosts never expand scope; no login is ever attempted by any
        check. Scanner transports that are not wired report NOT_CONFIGURED — honestly, never as success.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {notice ? <p>{notice}</p> : null}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12 }}>
        <StatCard label="Network Targets" value={targets.length} />
        <StatCard label="Active Hosts" value={hosts.length} />
        <StatCard label="Open Services" value={openServices} />
        <StatCard label="Sensitive Exposed" value={sensitiveExposed} />
        <StatCard label="V2 Plans" value={plans.length} />
        <StatCard label="Drift Events" value={drift.length} />
      </div>

      <Card title="New network target">
        <div style={{ display: "grid", gap: 8, maxWidth: 560 }}>
          <label>Asset ID <input value={form.assetId} onChange={(e) => setForm({ ...form, assetId: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Parent target ID (must be VERIFIED, with an APPROVED assessment)
            <input value={form.targetId} onChange={(e) => setForm({ ...form, targetId: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Target value (IP / CIDR / hostname)
            <input value={form.targetValue} placeholder="203.0.113.0/24" onChange={(e) => setForm({ ...form, targetValue: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Type
            <select value={form.targetType} onChange={(e) => setForm({ ...form, targetType: e.target.value })}>
              {["IP", "CIDR", "HOSTNAME", "AUTHORIZED_ASSET_GROUP"].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
          <label>
            <input type="checkbox" checked={form.internalEngagementApproved} onChange={(e) => setForm({ ...form, internalEngagementApproved: e.target.checked })} />
            {" "}Approved internal engagement covers private ranges (required for RFC 1918 targets; loopback/metadata always denied)
          </label>
          <button disabled={busy} onClick={() => void create()}>Create target</button>
        </div>
      </Card>

      <Card title="Targets">
        {targets.length === 0 ? <EmptyState title="No network targets yet." body="Create one from a verified asset above." /> : (
          <ul>
            {targets.map((t) => (
              <li key={t.id}>
                <Link href={`/vapt/network/targets/${t.id}`}>{t.targetValue}</Link>
                {" "}— {t.targetType} · {t.environment} · {t.criticality} · profile {t.scanProfileId} · {t.status}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Hosts">
        {hosts.length === 0 ? <EmptyState title="No hosts recorded." body="Hosts appear from governed discovery and asset inventory." /> : (
          <ul>
            {hosts.slice(0, 12).map((h) => (
              <li key={h.id}>
                <Link href={`/vapt/network/hosts/${h.id}`}>{h.host}</Link>
                {h.ip ? ` (${h.ip})` : ""} — zone {h.zone} · {h.openServices} open service(s)
                {h.internetExposedSensitive > 0 ? ` · ${h.internetExposedSensitive} sensitive exposed (risk signal, §99)` : ""}
              </li>
            ))}
          </ul>
        )}
        <p><Link href="/vapt/network/hosts">All hosts →</Link> · <Link href="/vapt/network/packet-analysis">Packet analysis →</Link></p>
      </Card>

      <Card title="Recent scan plans">
        {plans.length === 0 ? <EmptyState title="No plans yet." body="Plans are generated from a target's detail page — stages, tools, budget, blocked items and the frozen scope snapshot are shown before anything runs." /> : (
          <ul>
            {plans.slice(0, 10).map((p) => (
              <li key={p.id}>
                profile {p.profile} · {p.status} · tools: {Array.isArray(p.tools) ? p.tools.join(", ") : "—"}
                {p.scanId ? <> · <Link href={`/vapt/network/scans/${p.scanId}`}>scan detail</Link></> : null}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Recent drift (§101)">
        {drift.length === 0 ? <EmptyState title="No drift events." body="Drift appears when a scan posture is compared against a versioned baseline." /> : (
          <ul>
            {drift.slice(0, 8).map((d) => (
              <li key={d.id}>{d.kind} — {d.detail} · signal {d.riskSignal}</li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Tool health (§120)">
        <ul>
          {health.map((h) => (
            <li key={h.slug}><strong>{h.name}</strong> — {h.status} · {h.executionMode} · {h.notes}</li>
          ))}
        </ul>
        <p style={{ color: "var(--muted, #666)" }}>A scan with incomplete coverage completes as COMPLETED_WITH_GAPS; a failed scanner is a gap, never a clean result (§123/§155).</p>
      </Card>

      <Card title="Profiles (§15)">
        <ul>
          {PROFILES.map((p) => (
            <li key={p.key}><strong>{p.key}</strong> — {p.note}</li>
          ))}
        </ul>
      </Card>
    </main>
  );
}
