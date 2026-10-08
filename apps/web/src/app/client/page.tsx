"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface Dashboard {
  clientOrganizationId: string; portalRole: string;
  engagements: number; publishedFindings: number; unreadNotifications: number;
}

/**
 * Client portal dashboard (Prompt 37 §98/§99). Everything on this page
 * is scoped server-side to the signed-in client's own organization —
 * the portal API resolves the client binding from the account, never
 * from a parameter, and unpublished data simply does not exist here.
 */
export default function ClientDashboardPage() {
  const [dash, setDash] = useState<Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Dashboard>("/client/dashboard").then(setDash).catch((e: Error) => setError(e.message));
  }, []);

  return (
    <div>
      <PageHeader eyebrow="Client" title="Client Portal" body="Your published security findings and finalized reports" />
      {error && <p role="alert">{error}</p>}
      {dash && (
        <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))" }}>
          <Card><h3>Engagements</h3><p style={{ fontSize: 28 }}>{dash.engagements}</p>
            <Link href="/client/engagements">View engagements</Link></Card>
          <Card><h3>Published findings</h3><p style={{ fontSize: 28 }}>{dash.publishedFindings}</p>
            <Link href="/client/findings">View findings</Link></Card>
          <Card><h3>Notifications</h3><p style={{ fontSize: 28 }}>{dash.unreadNotifications} unread</p>
            <Link href="/client/reports">Finalized reports</Link></Card>
          <Card><h3>Remediation</h3><p>Track fixes, claim a fix, or request a retest.</p>
            <Link href="/client/remediation">Open remediation</Link></Card>
        </div>
      )}
      <p style={{ color: "#666", fontSize: 13 }}>
        Portal role: {dash?.portalRole ?? "—"}. Only findings and reports your security provider has
        published to your organization appear here.
      </p>
    </div>
  );
}
