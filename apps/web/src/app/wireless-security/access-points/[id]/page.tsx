"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card } from "@dsrclone/ui";

/**
 * Access-point detail (Prompt 19 §73). Posture evidence, rogue
 * classification, observations, configuration history (§55) and
 * correlated findings. BSSIDs are masked in ordinary views (§73);
 * stations are shown ONLY as workspace pseudonyms (§90) — a raw
 * client address never renders here.
 */
interface ApDetail {
  id: string; environmentId: string; bssid: string; ssid: string; ssidHidden: boolean;
  vendor?: string | null; channel?: number | null; frequencyMhz?: number | null; band?: string | null;
  securityMode: string; encryption?: string | null; authentication?: string | null; pmf: string;
  wpsAdvertised: boolean; signalDbm?: number | null; approvedStatus: string;
  firstSeen?: string | null; lastSeen?: string | null;
  stations: Array<{ addressFingerprint: string; associatedBssid?: string | null; signalDbm?: number | null; firstSeen?: string | null; lastSeen?: string | null }>;
  observations: Array<{ timestamp?: string | null; channel?: number | null; signalDbm?: number | null; securityMode: string; source: string }>;
  history: Array<{ ssid: string; channel?: number | null; securityMode: string; authentication?: string | null; approvedStatus: string; observedAt?: string | null }>;
  findings: Array<{ id: string; title: string; severity: string; status: string; wirelessFindingType?: string | null }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [ap, setAp] = useState<ApDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setAp(await apiFetch<ApDetail>(`/wireless/access-points/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load access point");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <Card><p className="text-sm text-red-300">{error}</p></Card>;
  if (!ap) return <Card><p className="text-sm text-slate-400">Loading…</p></Card>;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Wireless Security" title={ap.ssidHidden || !ap.ssid ? "(hidden SSID)" : ap.ssid} body={`BSSID ${ap.bssid} · observed passively — identity is the BSSID, the SSID is only a label (§5)`} />
      <Card>
        <h2 className="text-base font-semibold text-slate-100">Posture</h2>
        <div className="mt-2 flex flex-wrap gap-2">
          <Badge>{ap.securityMode}</Badge>
          {ap.encryption && <Badge>{ap.encryption}</Badge>}
          {ap.authentication && <Badge>{ap.authentication}</Badge>}
          <Badge>PMF {ap.pmf}</Badge>
          {ap.wpsAdvertised && <Badge>WPS advertised</Badge>}
          <Badge>{ap.approvedStatus}</Badge>
        </div>
        <p className="mt-2 text-sm text-slate-300">
          {ap.vendor ?? "Unknown vendor"} · channel {ap.channel ?? "—"} ({ap.band ?? "—"}) · {ap.signalDbm ?? "—"} dBm ·
          first seen {ap.firstSeen ?? "—"} · last seen {ap.lastSeen ?? "—"}
        </p>
        <p className="mt-2 text-xs text-slate-500">
          Rogue classification is a defensive indicator set (§44): SUSPICIOUS means
          &quot;investigate&quot; — it is never presented as a confirmed evil twin, and no action is
          ever taken against an observed AP.
        </p>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Findings</h2>
        {ap.findings.length === 0 && <p className="mt-2 text-sm text-slate-400">No findings recorded for this AP.</p>}
        <div className="mt-3 space-y-2">
          {ap.findings.map((f) => (
            <div key={f.id} className="rounded border border-slate-800 px-3 py-2 text-sm">
              <Badge>{f.severity}</Badge> <span className="text-slate-200">{f.title}</span>{" "}
              <span className="text-xs text-slate-500">{f.wirelessFindingType ?? ""} · {f.status}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Stations (pseudonymized)</h2>
        {ap.stations.length === 0 && <p className="mt-2 text-sm text-slate-400">No stations observed for this AP.</p>}
        <div className="mt-3 space-y-1 text-sm text-slate-300">
          {ap.stations.map((s) => (
            <div key={s.addressFingerprint} className="rounded border border-slate-800 px-3 py-2">
              {s.addressFingerprint} <span className="text-xs text-slate-500">· {s.signalDbm ?? "—"} dBm · last seen {s.lastSeen ?? "—"}</span>
            </div>
          ))}
        </div>
        <p className="mt-2 text-xs text-slate-500">Station identities are HMAC pseudonyms (§9). Raw addresses require an elevated, audited collection policy and never appear in ordinary views (§90).</p>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Configuration history</h2>
        {ap.history.length === 0 && <p className="mt-2 text-sm text-slate-400">No history recorded yet — history accrues as posture changes are observed (§55).</p>}
        <div className="mt-3 space-y-1 text-sm text-slate-300">
          {ap.history.map((h, i) => (
            <div key={i} className="rounded border border-slate-800 px-3 py-2">
              {h.securityMode} · {h.authentication ?? "—"} · ch {h.channel ?? "—"} · {h.approvedStatus}{" "}
              <span className="text-xs text-slate-500">{h.observedAt ?? ""}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Observations</h2>
        {ap.observations.length === 0 && <p className="mt-2 text-sm text-slate-400">No observations recorded.</p>}
        <div className="mt-3 space-y-1 text-sm text-slate-300">
          {ap.observations.slice(0, 20).map((o, i) => (
            <div key={i} className="rounded border border-slate-800 px-3 py-2">
              {o.securityMode} · ch {o.channel ?? "—"} · {o.signalDbm ?? "—"} dBm · {o.source}{" "}
              <span className="text-xs text-slate-500">{o.timestamp ?? ""}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
