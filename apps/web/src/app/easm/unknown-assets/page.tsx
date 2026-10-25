"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { EmptyState } from "@zerosweep/ui";

/**
 * Unknown/shadow asset review queue (Prompt 29 §97). Each item pairs
 * the asset with a recommended review action. "Unknown" is a state,
 * not an accusation.
 */
interface Item {
  id: string; normalizedValue: string; type: string; ownershipStatus: string;
  firstSeen: string; lastSeen: string; exposureState: string;
  recommendedReview: string; evidenceKinds: string[]; evidenceCount: number;
}

export default function Page() {
  const [items, setItems] = useState<Item[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<{ items: Item[] }>("/easm/unknown-assets");
      setItems(res.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const act = async (id: string, action: string) => {
    try {
      await apiFetch(`/easm/candidates/${id}`, { method: "PATCH", body: JSON.stringify({ action }) });
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Action failed.");
    }
  };

  return (
    <main>
      <PageHeader eyebrow="EASM" title="Unknown Assets" />
      <p style={{ color: "var(--muted, #666)", maxWidth: 720 }}>
        Newly discovered assets with unverified ownership. Confirm, assign an owner, or mark
        third-party — nothing here is scanned while it is unknown.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {items.length === 0 ? <EmptyState title="No unknown assets awaiting review." body="" /> : (
        <table>
          <thead>
            <tr><th>Asset</th><th>Type</th><th>Ownership</th><th>Exposure</th><th>Evidence</th><th>Recommended review</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {items.map((c) => (
              <tr key={c.id}>
                <td><Link href={`/easm/assets/${c.id}`}>{c.normalizedValue}</Link></td>
                <td>{c.type}</td>
                <td>{c.ownershipStatus}</td>
                <td>{c.exposureState}</td>
                <td>{c.evidenceKinds.join(", ") || "—"} ({c.evidenceCount})</td>
                <td>{c.recommendedReview}</td>
                <td>
                  <button onClick={() => act(c.id, "CONFIRM")}>Confirm ours</button>{" "}
                  <button onClick={() => act(c.id, "DECLARE_THIRD_PARTY")}>Third-party</button>{" "}
                  <button onClick={() => act(c.id, "REJECT")}>Reject</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
