"use client";

import { useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card } from "@zerosweep/ui";

/**
 * Mobile traffic view (Prompt 17 §99): sanitized proxy-session
 * metadata ONLY — hosts, request counts, bytes and sanitization
 * state. Sensitive bodies are never displayed by default (§68);
 * access is permission-gated and audited (MOBILE_TRAFFIC_ACCESSED,
 * §116). TLS interception exists only inside the lab with a
 * temporary CA that is removed after the session (§67) — never on
 * personal devices.
 */
interface TrafficData {
  id: string; buildId: string; deviceId?: string | null; proxyTool: string; status: string;
  hosts: Array<{ host: string; requests: number }>; requestCount: number;
  bytesCaptured: string; sanitizationState: string;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [sessionId, setSessionId] = useState("");
  const [data, setData] = useState<TrafficData | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const lookup = async () => {
    setBusy(true);
    setError("");
    setData(null);
    try {
      const d = await apiFetch<TrafficData>(`/mobile/traffic-sessions/${sessionId.trim()}`);
      setData(d);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Lookup failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Mobile Security" title="Mobile Traffic" body="Sanitized lab proxy sessions (mitmproxy / Burp connector). Metadata only — no sensitive bodies." />
      <Link href="/mobile-security" className="text-sm text-indigo-300 hover:underline">← Mobile Security</Link>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Traffic session lookup</h2>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm text-slate-400">Session ID
            <input className={`${inputCls} ml-2 w-80`} value={sessionId} onChange={(e) => setSessionId(e.target.value)} placeholder="traffic session id" />
          </label>
          <button disabled={busy || !sessionId.trim()} onClick={() => void lookup()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">
            {busy ? "Loading…" : "View session"}
          </button>
        </div>
        {error && <p className="mt-2 text-sm text-red-400">{error}</p>}
        <p className="mt-2 text-xs text-slate-500">Viewing a session is audited. Authorization headers, cookies and request/response bodies are redacted at capture (§68) and are not retrievable here.</p>
      </Card>

      {data && (
        <Card>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <span className="font-medium text-slate-100">{data.proxyTool}</span>
            <Badge>{data.status}</Badge>
            <Badge>{data.sanitizationState}</Badge>
            <span className="text-sm text-slate-400">{data.requestCount} requests · {data.bytesCaptured} bytes captured</span>
          </div>
          <h3 className="mb-2 text-sm font-medium text-slate-200">Observed hosts</h3>
          <ul className="space-y-1 text-sm text-slate-300">
            {data.hosts.map((h) => (
              <li key={h.host}><span className="font-mono text-xs">{h.host}</span> · {h.requests} requests</li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-slate-500">Hosts observed in app traffic join the endpoint inventory as DISCOVERED_REFERENCE — observation never authorizes a target (§30/§64).</p>
        </Card>
      )}
    </div>
  );
}
