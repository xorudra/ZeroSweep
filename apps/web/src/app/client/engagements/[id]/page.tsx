"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface ClientFinding {
  id: string; title: string; severity: string; status: string; riskScore: number | null;
  affectedAsset: string | null; dueAt: string | null;
}
interface ClientReport { id: string; title: string; type: string; version: string; finalizedAt: string | null }

/**
 * Engagement detail (Prompt 37 §98): the findings published to this
 * engagement and its finalized reports. Both lists come from the
 * portal API, which returns only published/finalized, client-safe
 * projections (§100/§101/§105).
 */
export default function ClientEngagementDetailPage() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [findings, setFindings] = useState<ClientFinding[]>([]);
  const [reports, setReports] = useState<ClientReport[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<ClientFinding[]>(`/client/engagements/${id}/findings`).then(setFindings).catch((e: Error) => setError(e.message));
    apiFetch<ClientReport[]>(`/client/engagements/${id}/reports`).then(setReports).catch(() => undefined);
  }, [id]);

  return (
    <div>
      <PageHeader eyebrow="Client Portal" title="Engagement" body="Published findings and finalized reports" />
      {error && <p role="alert">{error}</p>}
      <h2>Findings</h2>
      <div style={{ display: "grid", gap: 10 }}>
        {findings.map((f) => (
          <Card key={f.id}>
            <Link href={`/client/findings/${f.id}?engagement=${id}`}>{f.title}</Link>{" "}
            <Badge>{f.severity}</Badge> <Badge>{f.status}</Badge>
            <p style={{ color: "#666", fontSize: 13 }}>
              {f.affectedAsset ?? "—"}{f.riskScore != null ? ` · Risk ${f.riskScore}` : ""}
              {f.dueAt ? ` · Due ${new Date(f.dueAt).toLocaleDateString()}` : ""}
            </p>
          </Card>
        ))}
        {findings.length === 0 && <p>No findings have been published to this engagement yet.</p>}
      </div>
      <h2>Finalized reports</h2>
      <div style={{ display: "grid", gap: 10 }}>
        {reports.map((r) => (
          <Card key={r.id}>
            {r.title} <Badge>{r.type}</Badge>
            <p style={{ color: "#666", fontSize: 13 }}>Version {r.version}{r.finalizedAt ? ` · Finalized ${new Date(r.finalizedAt).toLocaleDateString()}` : ""}</p>
          </Card>
        ))}
        {reports.length === 0 && <p>No finalized reports yet — drafts and in-review reports are never shown here.</p>}
      </div>
    </div>
  );
}
