"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { EmptyState } from "@dsrclone/ui";

/**
 * Certificate intelligence (Prompt 29 §104): expiry states computed
 * from stored records, SAN inventory, issuers, and assets per
 * certificate. Certificates discovered via transparency logs create
 * candidates only — never authorization.
 */
interface Cert {
  id: string; commonName: string; issuer: string | null; subjectAlternativeNames: string[];
  notAfter: string; state: string; assets: number; serial: string | null;
}

export default function Page() {
  const [items, setItems] = useState<Cert[]>([]);
  const [summary, setSummary] = useState<Record<string, number>>({});
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<{ items: Cert[]; summary: Record<string, number> }>("/easm/certificates");
      setItems(res.items);
      setSummary(res.summary);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <main>
      <PageHeader eyebrow="EASM" title="Certificates" />
      <p>
        Healthy: {summary.HEALTHY ?? 0} · Expiring (≤30d): {summary.EXPIRING ?? 0} ·
        Urgent (≤7d): {summary.URGENT ?? 0} · Expired: {summary.EXPIRED ?? 0}
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {items.length === 0 ? <EmptyState title="No certificates recorded yet." body="" /> : (
        <table>
          <thead><tr><th>Common name</th><th>Issuer</th><th>SANs</th><th>Expires</th><th>State</th><th>Assets</th></tr></thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id}>
                <td>{c.commonName}</td>
                <td>{c.issuer ?? "—"}</td>
                <td>{c.subjectAlternativeNames.join(", ")}</td>
                <td>{new Date(c.notAfter).toLocaleDateString()}</td>
                <td>{c.state}</td>
                <td>{c.assets}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
