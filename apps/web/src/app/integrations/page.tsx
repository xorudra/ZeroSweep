"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Integrations" body="Connect DefectDojo, Faraday, Dradis, PlexTrac, Serpico and intelligence providers. Secrets are stored only as references in Credentials." />
      <ResourceList
        path="/integrations"
        emptyTitle="No integrations yet"
        emptyBody="Add an integration to export findings and reports to your vulnerability-management tooling."
        columns={['Name','Type','Enabled']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.name ?? ""), String(item.type ?? ""), item.enabled ? "Yes" : "No"]} />
        )}
      />
    </>
  );
}
