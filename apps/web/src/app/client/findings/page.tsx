"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface Engagement { id: string; name: string }

/**
 * Client portal findings index (Prompt 37 §98). Findings are always
 * scoped to an engagement server-side; this page routes into each
 * engagement's published list.
 */
export default function ClientFindingsIndexPage() {
  const [rows, setRows] = useState<Engagement[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<Engagement[]>("/client/engagements").then(setRows).catch((e: Error) => setError(e.message));
  }, []);
  return (
    <div>
      <PageHeader eyebrow="Client Portal" title="Findings" body="Choose an engagement to see its published findings" />
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
