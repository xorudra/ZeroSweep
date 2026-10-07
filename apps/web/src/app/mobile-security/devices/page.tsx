"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Device lab administration (Prompt 17 §98): DSRclone-managed
 * emulators and dedicated lab devices ONLY — personal devices are
 * never targeted (§55) and the DSRclone CA is never installed on
 * them (§67). There is deliberately NO remote shell, no arbitrary
 * ADB command box and no arbitrary script runner on this page or
 * anywhere in the product (§59/§75): lab work happens through
 * governed, approved dynamic sessions.
 */
interface DeviceRow {
  id: string; name: string; platform: string; deviceKind: string; osVersion?: string | null;
  availability: string; health: string; dedicatedNetwork: boolean; lastResetAt?: string | null; status: string;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [devices, setDevices] = useState<DeviceRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [platform, setPlatform] = useState<"ANDROID" | "IOS">("ANDROID");
  const [kind, setKind] = useState("EMULATOR");
  const [osVersion, setOsVersion] = useState("");

  const load = useCallback(async () => {
    try {
      const d = await apiFetch<{ items: DeviceRow[] }>("/mobile/devices");
      setDevices(d.items);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load devices");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const register = async () => {
    setBusy(true);
    setNotice("");
    try {
      await apiFetch("/mobile/devices", {
        method: "POST",
        body: JSON.stringify({ name, platform, deviceKind: kind, osVersion: osVersion || undefined, dedicatedNetwork: true, capabilities: [] }),
      });
      setNotice("Lab device registered on the dedicated test network. Devices are reset after each assessment (§57).");
      setName(""); setOsVersion("");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Registration failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Mobile Security" title="Mobile Device Lab" body="DSRclone-managed emulators and dedicated lab devices on an isolated test network." />
      <Link href="/mobile-security" className="text-sm text-indigo-300 hover:underline">← Mobile Security</Link>
      {notice && <p className="text-sm text-amber-300">{notice}</p>}
      {state === "error" && <p className="text-sm text-red-400">{error}</p>}

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Register lab device (MANAGE_DEVICE_LAB)</h2>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm text-slate-400">Name
            <input className={`${inputCls} ml-2`} value={name} onChange={(e) => setName(e.target.value)} placeholder="lab-emulator-1" />
          </label>
          <label className="text-sm text-slate-400">Platform
            <select className={`${inputCls} ml-2`} value={platform} onChange={(e) => setPlatform(e.target.value as "ANDROID" | "IOS")}>
              <option value="ANDROID">Android</option><option value="IOS">iOS</option>
            </select>
          </label>
          <label className="text-sm text-slate-400">Kind
            <select className={`${inputCls} ml-2`} value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="EMULATOR">Emulator</option><option value="DEDICATED_DEVICE">Dedicated device</option><option value="SIMULATOR">Simulator</option>
            </select>
          </label>
          <label className="text-sm text-slate-400">OS version
            <input className={`${inputCls} ml-2 w-24`} value={osVersion} onChange={(e) => setOsVersion(e.target.value)} placeholder="14" />
          </label>
          <button disabled={busy || !name} onClick={() => void register()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">
            {busy ? "Registering…" : "Register device"}
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500">Before any install, the lab verifies the build hash matches the approved build (§60). Test accounts are secret references; synthetic test data is preferred (§61).</p>
      </Card>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Devices</h2>
        {state === "ready" && devices.length === 0 && <EmptyState title="No lab devices" body="Register an emulator or dedicated device to enable controlled dynamic sessions." />}
        <div className="space-y-2">
          {devices.map((d) => (
            <div key={d.id} className="flex flex-wrap items-center justify-between gap-2 rounded bg-slate-900 px-3 py-2">
              <div>
                <p className="font-medium text-slate-100">{d.name}</p>
                <p className="text-xs text-slate-400">{d.deviceKind} · OS {d.osVersion ?? "—"} · {d.dedicatedNetwork ? "dedicated test network" : "network NOT dedicated"}{d.lastResetAt ? ` · last reset ${d.lastResetAt}` : ""}</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge>{d.platform}</Badge>
                <Badge>{d.availability}</Badge>
                <Badge>{d.health}</Badge>
              </div>
            </div>
          ))}
        </div>
        <p className="mt-3 text-xs text-slate-500">No generic remote shell exists for these devices — ADB access is the governed lab adapter inside an approved session only (§59). Dynamic workers (MOBILE_DYNAMIC_ANALYSIS) are isolated separately from static workers (§53).</p>
      </Card>
    </div>
  );
}
