"use client";

import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Scans" title="Scans" body="Scan executions of approved assessments, orchestrated as a stage DAG by queue workers. Mock-backed scans are simulation only — no real security tool runs in this phase." />
      <ResourceList
        path="/scans"
        emptyTitle="No scans yet"
        emptyBody="Start a scan from an approved assessment on a verified target (Assessments page → Start scan). Open a scan to watch its live pipeline, timeline and workers."
        columns={['Status', 'Progress', 'Stage', 'Started', '']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[
            String(item.status ?? ""),
            String(item.progress ?? 0) + "%",
            String(item.currentStage ?? "—"),
            String(item.startedAt ?? "—"),
            <Link key="view" href={`/scans/${String(item.id ?? "")}`} className="text-sky-400 hover:underline">Live view →</Link>,
          ]} />
        )}
      />
    </>
  );
}
