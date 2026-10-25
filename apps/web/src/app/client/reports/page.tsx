"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface Engagement { id: string; name: string }

/**
 * Client portal reports index (Prompt 37 §98/§105). Only FINALIZED
 * reports scoped to the client's organization are ever listed by the
 * API — drafts and in-review reports do not exist from here.
 */
export default function ClientReportsIndexPage() {
  const [rows, setRows] = useState<Engagement[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<Engagement[]>("/client/engagements").then(setRows).catch((e: Error) => setError(e.message));
  }, []);
  return (
    <div>
      <PageHeader eyebrow="Client Portal" title="Reports" body="Finalized reports are listed inside each engagement" />
      {error && <p role="alert">{error}</p>}
      <div style={{ display: "grid", gap: 10 }}>
        {rows.map((r) => (
          <Card key={r.id}><Link href={`/client/engagements/${r.id}`}>{r.name}</Link></Card>
        ))}
        {rows.length === 0 && !error && <p>No engagements yet.</p>}
      </div>
    </div>
  );
}
