"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Tool Registry" title="Tools" body="Every tool is integrated through a standard adapter with category, risk level, capabilities and health. Tools are never run from the API and there is no command box anywhere in DSRclone." />
      <ResourceList
        path="/tools"
        emptyTitle="No tools in the registry yet"
        emptyBody="Run the database seed to load the tool catalog (metadata only). Adapters are integrated phase by phase."
        columns={['Tool','Category','Risk','Health','Enabled']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.name ?? ""), String(item.category ?? ""), <Badge>{String(item.riskLevel ?? "")}</Badge>, String(item.healthStatus ?? ""), item.enabled ? "Yes" : "No"]} />
        )}
      />
    </>
  );
}
