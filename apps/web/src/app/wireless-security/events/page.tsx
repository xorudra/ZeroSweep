"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card } from "@zerosweep/ui";

/**
 * Wireless events & drift (Prompt 19 §76). Passively-detected
 * security events (§47) and configuration drift (§56). Detection
 * never triggers a transmission; a single ambiguous frame never
 * claims an attack (§49); drift is a configuration FACT, never an
 * accusation — a downgrade is a policy finding, not proof of malice.
 */
interface EventRow {
  id: string; environmentId: string; type: string; timestamp?: string | null;
  bssid?: string | null; confidence: string; evidenceSummary: string; source: string;
}
interface DriftRow {
  id: string; environmentId: string; kind: string; bssid: string; ssid: string;
  field: string; fromValue?: string | null; toValue?: string | null;
  securityDowngrade: boolean; detectedAt?: string | null;
}

export default function Page() {
  const [events, setEvents] = useState<EventRow[]>([]);
  const [drift, setDrift] = useState<DriftRow[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [e, d] = await Promise.all([
        apiFetch<{ items: EventRow[] }>("/wireless/events"),
        apiFetch<{ items: DriftRow[] }>("/wireless/drift"),
      ]);
      setEvents(e.items);
      setDrift(d.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load events");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Wireless Security" title="Wireless Events & Drift" body="Passive detection only — nothing on this page was produced by transmitting." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Security events</h2>
        {events.length === 0 && <p className="mt-2 text-sm text-slate-400">No events recorded.</p>}
        <div className="mt-3 space-y-2">
          {events.map((ev) => (
            <div key={ev.id} className="rounded border border-slate-800 px-3 py-2 text-sm">
              <Badge>{ev.type}</Badge> <Badge>confidence {ev.confidence}</Badge>{" "}
              <span className="text-slate-300">{ev.evidenceSummary}</span>
              <div className="mt-1 text-xs text-slate-500">
                {ev.bssid ?? ""} · {ev.timestamp ?? ""} · source {ev.source}
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Configuration drift</h2>
        {drift.length === 0 && <p className="mt-2 text-sm text-slate-400">No drift recorded. Drift appears when an AP&apos;s observed posture changes between sessions.</p>}
        <div className="mt-3 space-y-2">
          {drift.map((d) => (
            <div key={d.id} className="rounded border border-slate-800 px-3 py-2 text-sm">
              <Badge>{d.kind}</Badge>
              {d.securityDowngrade && <Badge>SECURITY DOWNGRADE</Badge>}{" "}
              <span className="text-slate-300">
                {d.ssid || "(hidden)"} · {d.bssid} · {d.field}: {d.fromValue ?? "—"} → {d.toValue ?? "—"}
              </span>
              <div className="mt-1 text-xs text-slate-500">{d.detectedAt ?? ""}</div>
            </div>
          ))}
        </div>
        <p className="mt-2 text-xs text-slate-500">
          Drift is a fact, not an accusation (§56): legitimate change control produces drift too.
          Retests are passive re-observations — an AP that is not observed again is INCONCLUSIVE,
          never auto-resolved (§59).
        </p>
      </Card>
    </div>
  );
}
