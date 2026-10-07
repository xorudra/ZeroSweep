"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Wireless environment detail (Prompt 19 §72). Scope, approved
 * profiles, inventory counts, the AP inventory and the gated scan
 * profiles. Scans start ONLY through the gated orchestration path —
 * the environment's target must be VERIFIED first (§94). Observed
 * networks are inventory, never targets.
 */
interface EnvironmentDetail {
  id: string; name: string; locationLabel?: string | null; environment: string;
  criticality: string; status: string;
  scope: {
    bssidAllowlist: string[]; ssidAllowlist: string[]; channelAllowlist: number[];
    frequencyBands: string[]; maxCaptureDurationSeconds: number; approvedInterfaces: string[];
  } | null;
  counts: { accessPoints: number; stations: number; sensors: number; captures: number; events: number; drift: number };
}
interface ApRow {
  id: string; bssid: string; ssid: string; ssidHidden: boolean; vendor?: string | null;
  channel?: number | null; band?: string | null; securityMode: string;
  encryption?: string | null; authentication?: string | null; pmf: string;
  wpsAdvertised: boolean; signalDbm?: number | null; approvedStatus: string;
}
const PROFILES = ["WIRELESS_PASSIVE_BASELINE", "WIRELESS_PASSIVE_COMPREHENSIVE", "PCAP_ANALYSIS_ONLY", "WIRELESS_COMPLIANCE", "WIRELESS_LAB_VALIDATION"] as const;

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [env, setEnv] = useState<EnvironmentDetail | null>(null);
  const [aps, setAps] = useState<ApRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [profile, setProfile] = useState<string>("WIRELESS_PASSIVE_BASELINE");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [e, a] = await Promise.all([
        apiFetch<EnvironmentDetail>(`/wireless/environments/${id}`),
        apiFetch<{ items: ApRow[] }>(`/wireless/access-points?environmentId=${id}`),
      ]);
      setEnv(e);
      setAps(a.items);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load environment");
      setState("error");
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  const startScan = async () => {
    setBusy(true);
    try {
      const res = await apiFetch<{ scanId?: string }>(`/wireless/environments/${id}/scan`, {
        method: "POST", body: JSON.stringify({ profile }),
      });
      setNotice(`Scan started (${res.scanId ?? "queued"}) with profile ${profile}. Passive stages run on sensor workers only; without an approved sensor/capture the run reports NOT_CONFIGURED honestly.`);
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Failed to start scan");
    } finally {
      setBusy(false);
    }
  };

  if (state === "error") return <Card><p className="text-sm text-red-300">{error}</p></Card>;
  if (!env) return <Card><p className="text-sm text-slate-400">Loading…</p></Card>;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Wireless Security" title={env.name} body={`${env.environment} · ${env.criticality} · ${env.status}`} />
      {notice && <Card><p className="text-sm text-emerald-300">{notice}</p></Card>}

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Inventory</h2>
        <p className="mt-2 text-sm text-slate-300">
          {env.counts.accessPoints} access points · {env.counts.stations} stations (pseudonymized) ·{" "}
          {env.counts.sensors} sensors · {env.counts.captures} captures · {env.counts.events} events · {env.counts.drift} drift records
        </p>
        {env.scope && (
          <p className="mt-2 text-xs text-slate-400">
            Scope (§4): {env.scope.ssidAllowlist.length} SSIDs · {env.scope.bssidAllowlist.length} BSSIDs · channels{" "}
            {env.scope.channelAllowlist.join(", ") || "—"} · bands {env.scope.frequencyBands.join(", ") || "—"} ·
            approved interfaces {env.scope.approvedInterfaces.join(", ") || "—"} · max capture {env.scope.maxCaptureDurationSeconds}s.
            Authorization is never inferred from detectability.
          </p>
        )}
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Start passive scan</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <select className="rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700" value={profile} onChange={(e) => setProfile(e.target.value)}>
            {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <button className="rounded bg-sky-600 px-3 py-1.5 text-sm text-white disabled:opacity-50" disabled={busy} onClick={() => void startScan()}>
            Start scan
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500">
          Every profile is passive: baseline profiles can never select Wifite or active hcxdumptool
          modes (§64), and the lab profile is a governed architecture record — nothing transmits.
        </p>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Access points</h2>
        {aps.length === 0 && (
          <EmptyState title="No access points observed" body="APs appear after a passive sensor collection or an approved capture analysis. Nothing here is simulated." />
        )}
        <div className="mt-3 space-y-2">
          {aps.map((ap) => (
            <div key={ap.id} className="flex flex-wrap items-center gap-3 rounded border border-slate-800 px-3 py-2 text-sm">
              <Link className="text-sky-300 hover:underline" href={`/wireless-security/access-points/${ap.id}`}>
                {ap.ssidHidden || !ap.ssid ? "(hidden SSID)" : ap.ssid}
              </Link>
              <span className="text-xs text-slate-400">{ap.bssid}</span>
              <Badge>{ap.securityMode}</Badge>
              {ap.encryption && <Badge>{ap.encryption}</Badge>}
              {ap.authentication && <Badge>{ap.authentication}</Badge>}
              <Badge>{ap.approvedStatus}</Badge>
              <span className="text-xs text-slate-500">
                ch {ap.channel ?? "—"} · {ap.band ?? ""} · PMF {ap.pmf}{ap.wpsAdvertised ? " · WPS" : ""} · {ap.signalDbm ?? "—"} dBm
              </span>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Captures</h2>
        <p className="mt-2 text-sm text-slate-400">
          Captures are approved through the captures workflow; raw references are permission-gated
          and every raw read is audited (§30). Open an environment&apos;s captures from the API or
          the capture detail page when a scan registers one.
        </p>
        <p className="mt-2 text-xs text-slate-500">
          <Link className="text-sky-300 hover:underline" href="/wireless-security/sensors">Manage sensors</Link>
          {" · "}
          <Link className="text-sky-300 hover:underline" href="/wireless-security/events">Events &amp; drift</Link>
        </p>
      </Card>
    </div>
  );
}
