"use client";

import { useState } from "react";
import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { AssessmentActions } from "@/components/AssessmentActions";
import { CreateAssessment, PendingApprovals } from "@/components/AssessmentCreate";
import { Badge } from "@zerosweep/ui";

export default function Page() {
  const [refreshKey, setRefreshKey] = useState(0);
  const bump = () => setRefreshKey((k) => k + 1);
  return (
    <>
      <PageHeader eyebrow="Assessments — step 2" title="Assessments" body="An assessment is your permission slip for one check: a verified target, a kind of check, and your approval. Scans only ever run from an approved assessment." />
      <CreateAssessment onChanged={bump} />
      <PendingApprovals refreshKey={refreshKey} onChanged={bump} />
      <ResourceList
        key={refreshKey}
        path="/assessments"
        emptyTitle="No assessments yet"
        emptyBody="Use the form above: pick a verified target, choose a kind of check, create it, then approve it here."
        columns={['Name','Profile','Status','Target']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.name ?? ""), String(item.profile ?? ""), String(item.status ?? ""), String((item.target as Record<string, unknown> | undefined)?.value ?? "")]} />
        )}
      />
      <AssessmentActions key={`actions-${refreshKey}`} />
    </>
  );
}
