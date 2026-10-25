"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@zerosweep/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Integrations" body="Vulnerability-management platforms (DefectDojo, Faraday, Dradis, PlexTrac, Serpico) plus the Prompt 24 enterprise set — GitHub, GitLab, Bitbucket, Jira, Slack, Microsoft Teams, SIEM and generic webhooks. Credentials are secret references only; manage enterprise integrations under Settings → Integrations." />
      <ResourceList
        path="/integrations"
        emptyTitle="No integrations yet"
        emptyBody="Add an integration to sync findings, tickets and events with your security tooling."
        columns={['Name','Type','Status','Enabled','Credential']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[
            String(item.name ?? ""),
            String(item.type ?? ""),
            <Badge key="s" tone={item.status === "CONNECTED" ? "ok" : item.status === "DEGRADED" ? "high" : "neutral"}>{String(item.status ?? "PENDING")}</Badge>,
            item.enabled ? "Yes" : "No",
            item.secretConfigured ? "Configured (reference)" : "Not configured",
          ]} />
        )}
      />
    </>
  );
}
