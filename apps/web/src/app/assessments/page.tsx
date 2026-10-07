"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Assessments" title="Assessments" body="An assessment is your authorized engagement: target, scope, profile and approval. Scans are executions of an approved assessment." />
      <ResourceList
        path="/assessments"
        emptyTitle="No assessments yet"
        emptyBody="Create an assessment from a verified target, choose a profile (Passive Recon, Web Baseline, Web Comprehensive, API, Network, Source Code, Container, Cloud, Mobile or Custom), and get it approved."
        columns={['Name','Profile','Status','Target']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.name ?? ""), String(item.profile ?? ""), String(item.status ?? ""), String((item.target as Record<string, unknown> | undefined)?.value ?? "")]} />
        )}
      />
    </>
  );
}
