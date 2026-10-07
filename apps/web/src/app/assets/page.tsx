"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Assets" title="Assets" body="Hosts, services, endpoints and technologies discovered from verified targets during approved scans." />
      <ResourceList
        path="/targets"
        emptyTitle="No assets yet"
        emptyBody="Assets are discovered by scans of verified targets. Nothing has been discovered yet."
        columns={['Host','Type','Target']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.host ?? item.name ?? ""), String(item.type ?? ""), String(item.targetId ?? "")]} />
        )}
      />
    </>
  );
}
