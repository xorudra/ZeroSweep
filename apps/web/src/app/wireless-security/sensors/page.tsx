"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Wireless sensors (Prompt 19 §74). Dedicated approved sensors are
 * the ONLY collection path (§11–§14): a sensor is approved against
 * its environment's approved interface list, and collection runs on
 * WIRELESS_PASSIVE_ANALYSIS workers — wireless interfaces are never
 * exposed to the web, the API or general workers. Health is reported
 * honestly: with no provisioned sensor transport a sensor shows
 * UNKNOWN rather than a fabricated feed.
 */
interface SensorRow {
  id: string; environmentId?: string | null; name: string; host?: string | null;
  adapter?: string | null; driver?: string | null; interfaceName?: string | null;
  supportedBands: string[]; monitorModeCapable: boolean; health: string; status: string;
  lastSeen?: string | null;
}
interface EnvironmentLite { id: string; name: string }

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [sensors, setSensors] = useState<SensorRow[]>([]);
  const [environments, setEnvironments] = useState<EnvironmentLite[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [name, setName] = useState("");
  const [environmentId, setEnvironmentId] = useState("");
  const [interfaceName, setInterfaceName] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [s, e] = await Promise.all([
        apiFetch<{ items: SensorRow[] }>("/wireless/sensors"),
        apiFetch<{ items: EnvironmentLite[] }>("/wireless/environments"),
      ]);
      setSensors(s.items);
      setEnvironments(e.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load sensors");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const register = async () => {
    setBusy(true);
    try {
      await apiFetch("/wireless/sensors", {
        method: "POST",
        body: JSON.stringify({
          name, environmentId: environmentId || undefined,
          interfaceName: interfaceName || undefined, monitorModeCapable: true,
          supportedBands: ["2.4GHZ", "5GHZ"],
        }),
      });
      setNotice("Sensor registered. Approve it (its interface must be in the environment's approved list) before any collection.");
      setName("");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Failed to register sensor");
    } finally {
      setBusy(false);
    }
  };

  const approve = async (sensorId: string) => {
    try {
      await apiFetch(`/wireless/sensors/${sensorId}/approve`, { method: "POST", body: "{}" });
      setNotice("Sensor approved (ACTIVE).");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Approval failed");
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Wireless Security" title="Wireless Sensors" body="Dedicated, approved collection sensors — the only path to live passive observation." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {notice && <Card><p className="text-sm text-emerald-300">{notice}</p></Card>}

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Register sensor</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <input className={inputCls} placeholder="Sensor name" value={name} onChange={(e) => setName(e.target.value)} />
          <select className={inputCls} value={environmentId} onChange={(e) => setEnvironmentId(e.target.value)}>
            <option value="">Environment…</option>
            {environments.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
          </select>
          <input className={inputCls} placeholder="Interface (e.g. wlan1)" value={interfaceName} onChange={(e) => setInterfaceName(e.target.value)} />
          <button className="rounded bg-sky-600 px-3 py-1.5 text-sm text-white disabled:opacity-50" disabled={busy || !name} onClick={() => void register()}>
            Register
          </button>
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Sensors</h2>
        {sensors.length === 0 && (
          <EmptyState title="No sensors registered" body="Without an approved sensor, live discovery stages report NOT_CONFIGURED — recorded captures can still be analyzed offline." />
        )}
        <div className="mt-3 space-y-2">
          {sensors.map((s) => (
            <div key={s.id} className="flex flex-wrap items-center gap-3 rounded border border-slate-800 px-3 py-2 text-sm">
              <span className="text-slate-100">{s.name}</span>
              <Badge>{s.status}</Badge>
              <Badge>health {s.health}</Badge>
              <span className="text-xs text-slate-400">
                {s.adapter ?? "adapter —"} · {s.interfaceName ?? "no interface"} · bands {s.supportedBands.join(", ") || "—"}
                {s.monitorModeCapable ? " · monitor-mode capable" : ""}
              </span>
              {s.status !== "ACTIVE" && (
                <button className="ml-auto rounded bg-slate-700 px-2 py-1 text-xs text-white" onClick={() => void approve(s.id)}>
                  Approve
                </button>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
