"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface Engagement { id: string; name: string }
interface ClientFinding { id: string; title: string; severity: string; status: string; verification: string }

/**
 * Client remediation view (Prompt 37 §98). Published findings with
 * their client-visible status; fix claims and retest requests go
 * through the governed portal actions — a claim never marks a finding
 * verified (§103/§30).
 */
export default function ClientRemediationPage() {
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [findings, setFindings] = useState<ClientFinding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Engagement[]>("/client/engagements").then((rows) => {
      setEngagements(rows);
      if (rows[0]) setSelected(rows[0].id);
    }).catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => {
    if (!selected) return;
    apiFetch<ClientFinding[]>(`/client/engagements/${selected}/findings`).then(setFindings).catch((e: Error) => setError(e.message));
  }, [selected]);

  return (
    <div>
      <PageHeader eyebrow="Client Portal" title="Remediation" body="Track published findings and their fix status" />
      {error && <p role="alert">{error}</p>}
      <label>
        Engagement{" "}
        <select value={selected} onChange={(e) => setSelected(e.target.value)}>
          {engagements.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
        </select>
      </label>
      <div style={{ display: "grid", gap: 10, marginTop: 12 }}>
        {findings.map((f) => (
          <Card key={f.id}>
            <Link href={`/client/findings/${f.id}?engagement=${selected}`}>{f.title}</Link>{" "}
            <Badge>{f.severity}</Badge> <Badge>{f.status}</Badge>
            <p style={{ color: "#666", fontSize: 13 }}>Verification: {f.verification}</p>
          </Card>
        ))}
        {findings.length === 0 && <p>Nothing published here yet.</p>}
      </div>
    </div>
  );
}
