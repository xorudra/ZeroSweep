"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface Engagement { id: string; name: string; status: string; reportVisibility: string; createdAt: string }

/** Client portal — my engagements (Prompt 37 §98). */
export default function ClientEngagementsPage() {
  const [rows, setRows] = useState<Engagement[]>([]);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<Engagement[]>("/client/engagements").then(setRows).catch((e: Error) => setError(e.message));
  }, []);
  return (
    <div>
      <PageHeader eyebrow="Client Portal" title="My Engagements" body="Security engagements published to your organization" />
      {error && <p role="alert">{error}</p>}
      <div style={{ display: "grid", gap: 10 }}>
        {rows.map((r) => (
          <Card key={r.id}>
            <Link href={`/client/engagements/${r.id}`}>{r.name}</Link>
            <p style={{ color: "#666", fontSize: 13 }}>{r.status} · Reports: {r.reportVisibility} · Since {new Date(r.createdAt).toLocaleDateString()}</p>
          </Card>
        ))}
        {rows.length === 0 && !error && <p>No engagements yet.</p>}
      </div>
    </div>
  );
}
