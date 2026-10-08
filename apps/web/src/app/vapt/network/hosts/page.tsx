"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@dsrclone/ui";

/**
 * Network hosts (Prompt 33 §114): the canonical host inventory with
 * zone/exposure/risk context. Filters: search text + zone. Exposure of
 * a sensitive service is a risk signal — never labelled a
 * vulnerability by itself (§99).
 */
interface HostRow {
  id: string; host: string; ip?: string | null; osHint?: string | null; network?: string | null;
  zone: string; criticality: string; openServices: number; internetExposedSensitive: number;
}

export default function Page() {
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [q, setQ] = useState("");
  const [zone, setZone] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const qs = new URLSearchParams();
      if (q) qs.set("q", q);
      if (zone) qs.set("zone", zone);
      setHosts(await apiFetch<HostRow[]>(`/vapt/network/hosts${qs.toString() ? `?${qs}` : ""}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [q, zone]);

  useEffect(() => { void load(); }, [load]);

  return (
    <main>
      <PageHeader eyebrow="Network VAPT V2" title="Hosts" />
      {error ? <p role="alert">{error}</p> : null}
      <Card title="Filters">
        <label>Search <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="host or IP" /></label>{" "}
        <label>Zone{" "}
          <select value={zone} onChange={(e) => setZone(e.target.value)}>
            <option value="">Any</option>
            {["INTERNET", "DMZ", "INTERNAL", "RESTRICTED", "MANAGEMENT", "UNKNOWN"].map((z) => <option key={z} value={z}>{z}</option>)}
          </select>
        </label>
      </Card>
      <Card title={`Hosts (${hosts.length})`}>
        {hosts.length === 0 ? <EmptyState title="No hosts match." body="Hosts come from governed discovery + asset inventory — never from scope expansion (§12)." /> : (
          <table>
            <thead><tr><th>Host</th><th>IP</th><th>Network</th><th>Zone</th><th>OS hint</th><th>Open services</th><th>Sensitive exposed</th></tr></thead>
            <tbody>
              {hosts.map((h) => (
                <tr key={h.id}>
                  <td><Link href={`/vapt/network/hosts/${h.id}`}>{h.host}</Link></td>
                  <td>{h.ip ?? "—"}</td>
                  <td>{h.network ?? "—"}</td>
                  <td>{h.zone}</td>
                  <td>{h.osHint ?? "—"}</td>
                  <td>{h.openServices}</td>
                  <td>{h.internetExposedSensitive > 0 ? `${h.internetExposedSensitive} (risk signal)` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <p><Link href="/vapt/network">← Back to Network VAPT</Link></p>
    </main>
  );
}
