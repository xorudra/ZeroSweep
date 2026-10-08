"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { EmptyState } from "@dsrclone/ui";

/**
 * Technology intelligence (Prompt 29 §103). Confidence comes from
 * independent-source agreement; when only the technology family is
 * known, the version stays blank rather than guessed.
 */
interface TechGroup { technology: string; assets: number; versions: Array<string | null>; confidenceLevels: string[] }

export default function Page() {
  const [items, setItems] = useState<TechGroup[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<{ items: TechGroup[] }>("/easm/technologies");
      setItems(res.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <main>
      <PageHeader eyebrow="EASM" title="External Technologies" />
      <p style={{ color: "var(--muted, #666)", maxWidth: 720 }}>
        Observed from passive fingerprints and authorized observations only. A technology
        observation is not a vulnerability — KEV/EOL exposure is checked against the unified
        vulnerability intelligence, not assumed here.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {items.length === 0 ? <EmptyState title="No technologies observed yet." body="" /> : (
        <table>
          <thead><tr><th>Technology</th><th>Assets</th><th>Versions observed</th><th>Confidence</th></tr></thead>
          <tbody>
            {items.map((t) => (
              <tr key={t.technology}>
                <td>{t.technology}</td>
                <td>{t.assets}</td>
                <td>{t.versions.filter(Boolean).join(", ") || "family only"}</td>
                <td>{t.confidenceLevels.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
