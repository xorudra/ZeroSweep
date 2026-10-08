"use client";

import { Suspense, useEffect, useState } from "react";
import { useParams, useSearchParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface ClientFindingDetail {
  id: string; title: string; description: string; severity: string; status: string;
  verification: string; affectedAsset: string | null; impact: string | null;
  remediation: string | null; cve: string | null; cwe: string | null; dueAt: string | null;
  evidence: { id: string; summary: string; type: string }[];
  comments: { id: string; text: string; createdAt: string }[];
}

/**
 * Client finding detail (Prompt 37 §98/§100). The API returns the
 * client-safe projection only: client-visible evidence and comments,
 * redacted text, no internal workflow data. The engagement comes from
 * the link that led here; without a publication the API answers 404.
 */
function FindingDetail() {
  const params = useParams<{ id: string }>();
  const search = useSearchParams();
  const engagement = search.get("engagement") ?? "";
  const [finding, setFinding] = useState<ClientFindingDetail | null>(null);
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = () => {
    if (!engagement) { setError("Open this finding from its engagement page."); return; }
    apiFetch<ClientFindingDetail>(`/client/engagements/${engagement}/findings/${params.id}`)
      .then(setFinding).catch((e: Error) => setError(e.message));
  };
  useEffect(load, [engagement, params.id]);

  const post = async (path: string, body?: object, ok?: string) => {
    setError(null); setNotice(null);
    try {
      await apiFetch(`/client/engagements/${engagement}/findings/${params.id}/${path}`, {
        method: "POST", body: JSON.stringify(body ?? {}),
      });
      setNotice(ok ?? "Done.");
      if (path === "comments") { setComment(""); load(); }
    } catch (e) { setError((e as Error).message); }
  };

  if (!finding) return <div><PageHeader eyebrow="Client Portal" title="Finding" />{error && <p role="alert">{error}</p>}</div>;
  return (
    <div>
      <PageHeader eyebrow="Client Portal" title={finding.title} body="Published finding — client view" />
      {error && <p role="alert">{error}</p>}
      {notice && <p>{notice}</p>}
      <p><Badge>{finding.severity}</Badge> <Badge>{finding.status}</Badge> <Badge>{finding.verification}</Badge></p>
      <Card>
        <h3>Description</h3><p>{finding.description}</p>
        {finding.impact && <><h3>Impact</h3><p>{finding.impact}</p></>}
        {finding.remediation && <><h3>Remediation guidance</h3><p>{finding.remediation}</p></>}
        <p style={{ color: "#666", fontSize: 13 }}>
          Asset: {finding.affectedAsset ?? "—"}{finding.cve ? ` · ${finding.cve}` : ""}{finding.cwe ? ` · ${finding.cwe}` : ""}
          {finding.dueAt ? ` · Due ${new Date(finding.dueAt).toLocaleDateString()}` : ""}
        </p>
      </Card>
      <h3>Evidence shared with you</h3>
      {finding.evidence.map((e) => <Card key={e.id}><p>{e.summary}</p></Card>)}
      {finding.evidence.length === 0 && <p>No evidence has been shared for this finding.</p>}
      <h3>Discussion</h3>
      {finding.comments.map((c) => (
        <Card key={c.id}><p>{c.text}</p><p style={{ color: "#666", fontSize: 12 }}>{new Date(c.createdAt).toLocaleString()}</p></Card>
      ))}
      <textarea value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Add a comment for the security team" rows={3} style={{ width: "100%" }} />
      <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
        <button onClick={() => post("comments", { text: comment }, "Comment added.")}>Add comment</button>
        <button onClick={() => post("fix-claimed", {}, "Fix claimed. The security team will verify it — a claim is not a verified closure.")}>Claim fix</button>
        <button onClick={() => post("request-retest", {}, "Retest requested.")}>Request retest</button>
      </div>
    </div>
  );
}

export default function ClientFindingDetailPage() {
  return <Suspense fallback={<p>Loading…</p>}><FindingDetail /></Suspense>;
}
