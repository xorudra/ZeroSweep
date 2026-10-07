"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Findings" title="Findings" body="Normalized, deduplicated findings from every scanner — with severity, CVSS, CVE/CWE, evidence and remediation." />
      <ResourceList
        path="/findings"
        emptyTitle="No findings yet"
        emptyBody="Findings appear only after real authorized scans. DSRclone never displays placeholder vulnerabilities."
        columns={['Severity','Title','Status','Verification']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[<Badge tone={String(item.severity ?? "")}>{String(item.severity ?? "")}</Badge>, String(item.title ?? ""), String(item.status ?? ""), String(item.verificationStatus ?? "")]} />
        )}
      />
    </>
  );
}
