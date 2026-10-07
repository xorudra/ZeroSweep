"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Scans" title="Scans" body="Scan executions with live stage progress. In this foundation phase scans are queued and orchestration is a placeholder — no security tool runs yet." />
      <ResourceList
        path="/scans"
        emptyTitle="No scans yet"
        emptyBody="Request a scan from an approved assessment on a verified target. Progress, stages and worker status will stream here."
        columns={['Status','Progress','Stage','Started']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.status ?? ""), String(item.progress ?? 0) + "%", String(item.currentStage ?? "—"), String(item.startedAt ?? "—")]} />
        )}
      />
    </>
  );
}
