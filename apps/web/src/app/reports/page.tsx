"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Reports" title="Reports" body="Professional assessment reports — cover, executive summary, methodology, scope and authorization, findings, evidence and retest results." />
      <ResourceList
        path="/reports"
        emptyTitle="No reports yet"
        emptyBody="Generate a report from a completed scan. Formats: PDF, HTML, JSON, CSV."
        columns={['Format','Status','Generated']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.format ?? ""), String(item.status ?? ""), String(item.generatedAt ?? "—")]} />
        )}
      />
    </>
  );
}
