"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { EmptyState } from "@dsrclone/ui";

/**
 * External asset inventory (Prompt 29 §99). Filters mirror the API:
 * type, ownership, authorization (active-testing status), exposure,
 * lifecycle. Candidates are not scan targets.
 */
interface Candidate {
  id: string; normalizedValue: string; type: string; status: string; lifecycle: string;
  ownershipStatus: string; ownershipConfidence: string; activeTestingStatus: string;
  exposureState: string; firstSeen: string; lastSeen: string;
}

export default function Page() {
  const [items, setItems] = useState<Candidate[]>([]);
  const [error, setError] = useState("");
  const [ownership, setOwnership] = useState("");
  const [exposure, setExposure] = useState("");
  const [query, setQuery] = useState("");

  const load = useCallback(async () => {
    try {
      if (query.trim()) {
        const res = await apiFetch<{ items: Candidate[] }>(`/easm/search?q=${encodeURIComponent(query.trim())}`);
        setItems(res.items);
        return;
      }
      const params = new URLSearchParams();
      if (ownership) params.set("ownershipStatus", ownership);
      if (exposure) params.set("exposureState", exposure);
      const res = await apiFetch<{ items: Candidate[] }>(`/easm/assets?${params.toString()}`);
      setItems(res.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [ownership, exposure, query]);

  useEffect(() => { void load(); }, [load]);

  return (
    <main>
      <PageHeader eyebrow="EASM" title="External Assets" />
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <select value={ownership} onChange={(e) => setOwnership(e.target.value)}>
          <option value="">All ownership</option>
          <option value="UNKNOWN">Unknown</option>
          <option value="LIKELY">Likely</option>
          <option value="VERIFIED">Verified</option>
          <option value="THIRD_PARTY">Third-party</option>
          <option value="SHARED">Shared</option>
        </select>
        <select value={exposure} onChange={(e) => setExposure(e.target.value)}>
          <option value="">All exposure</option>
          <option value="INTERNET_EXPOSED">Internet exposed</option>
          <option value="CONDITIONALLY_EXPOSED">Conditionally exposed</option>
          <option value="NOT_OBSERVED">Not observed</option>
          <option value="UNKNOWN">Unknown</option>
        </select>
        <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search: ownership:unknown technology:wordpress service:22" style={{ flex: 1, minWidth: 260 }} />
      </div>
      {error ? <p role="alert">{error}</p> : null}
      {items.length === 0 ? <EmptyState title="No external assets match." body="" /> : (
        <table>
          <thead>
            <tr><th>Asset</th><th>Type</th><th>Ownership</th><th>Active testing</th><th>Exposure</th><th>Lifecycle</th><th>First seen</th><th>Last seen</th></tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id}>
                <td><Link href={`/easm/assets/${c.id}`}>{c.normalizedValue}</Link></td>
                <td>{c.type}</td>
                <td>{c.ownershipStatus} ({c.ownershipConfidence})</td>
                <td>{c.activeTestingStatus}</td>
                <td>{c.exposureState}</td>
                <td>{c.lifecycle}</td>
                <td>{new Date(c.firstSeen).toLocaleDateString()}</td>
                <td>{new Date(c.lastSeen).toLocaleDateString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
