"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@zerosweep/ui";

/**
 * Packet analysis (Prompt 33 §119, §83–§93): authorized captures,
 * protocol summaries and security observations. Captures are passive,
 * bounded and permissioned (CREATE_PACKET_CAPTURE /
 * VIEW_PACKET_CAPTURE); summaries never expose credentials, tokens or
 * payload content (§90), and PCAP bytes stay in restricted storage
 * (§88). In this deployment the capture transport is NOT_CONFIGURED —
 * requests are recorded with their bounds, never fabricated.
 */
interface Capture {
  id: string; interfaceReference: string; durationSeconds: number; sizeLimitBytes: number;
  status: string; transport: string; createdAt: string; evidenceRef?: string | null;
}

export default function Page() {
  const [captures, setCaptures] = useState<Capture[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [form, setForm] = useState({ interfaceReference: "", durationSeconds: 300, sizeLimitBytes: 100_000_000, interfaceAuthorized: false });
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try { setCaptures(await apiFetch<Capture[]>("/vapt/network/packet-captures")); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Could not reach the API (packet captures need VIEW_PACKET_CAPTURE)."); }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    setBusy(true); setNotice("");
    try {
      const row = await apiFetch<Capture & { note?: string }>("/vapt/network/packet-captures", { method: "POST", body: JSON.stringify(form) });
      setNotice(row.note ?? "Capture recorded.");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Capture request failed.");
    } finally { setBusy(false); }
  };

  return (
    <main>
      <PageHeader eyebrow="Network VAPT V2" title="Packet Analysis" />
      <p style={{ color: "var(--muted, #666)", maxWidth: 820 }}>
        Passive capture only — the platform never injects or modifies traffic (§85/§93). Duration and size
        are hard-bounded (§87); oversized requests are rejected, not clamped (§151).
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {notice ? <p>{notice}</p> : null}

      <Card title="Request a capture (§84)">
        <div style={{ display: "grid", gap: 8, maxWidth: 560 }}>
          <label>Interface reference (worker configuration reference, never a raw device path)
            <input value={form.interfaceReference} placeholder="worker-1/eth0" onChange={(e) => setForm({ ...form, interfaceReference: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Duration (seconds, max 3600)
            <input type="number" value={form.durationSeconds} onChange={(e) => setForm({ ...form, durationSeconds: Number(e.target.value) })} style={{ width: "100%" }} /></label>
          <label>Size limit (bytes, max 2 GiB)
            <input type="number" value={form.sizeLimitBytes} onChange={(e) => setForm({ ...form, sizeLimitBytes: Number(e.target.value) })} style={{ width: "100%" }} /></label>
          <label>
            <input type="checkbox" checked={form.interfaceAuthorized} onChange={(e) => setForm({ ...form, interfaceAuthorized: e.target.checked })} />
            {" "}Interface is authorized for capture on an approved internal engagement
          </label>
          <button disabled={busy} onClick={() => void create()}>Request capture</button>
        </div>
      </Card>

      <Card title="Captures">
        {captures.length === 0 ? <EmptyState title="No captures recorded." body="Captures appear here once requested under CREATE_PACKET_CAPTURE." /> : (
          <ul>
            {captures.map((c) => (
              <li key={c.id}>
                {c.interfaceReference} · {c.durationSeconds}s · {(c.sizeLimitBytes / 1_000_000).toFixed(1)} MB cap · {c.status} · transport {c.transport}
                {c.evidenceRef ? ` · evidence ${c.evidenceRef}` : ""} · {new Date(c.createdAt).toLocaleString()}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <p><Link href="/vapt/network">← Back to Network VAPT</Link></p>
    </main>
  );
}
