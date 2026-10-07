"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Targets" title="Targets" body="Register targets you own or are authorized to assess. A target must be verified and in scope before any scan can run." />
      <ResourceList
        path="/targets"
        emptyTitle="No targets yet"
        emptyBody="Add your first target — a domain, web application, IP, API, repository, image or lab environment — then verify ownership to continue."
        columns={['Name','Type','Value','Status','Verified']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.name ?? ""), String(item.type ?? ""), String(item.value ?? ""), String(item.status ?? ""), item.verified ? <Badge tone="VERIFIED">Verified</Badge> : <Badge tone="PENDING">Pending</Badge>]} />
        )}
      />
    </>
  );
}
