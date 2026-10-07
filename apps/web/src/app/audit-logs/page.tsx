"use client";

import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge } from "@dsrclone/ui";

export default function Page() {
  return (
    <>
      <PageHeader eyebrow="Audit Logs" title="Audit Logs" body="Every security-relevant action — logins, target changes, approvals, scan requests and report generation — is recorded." />
      <ResourceList
        path="/audit-logs"
        emptyTitle="No audit entries yet"
        emptyBody="Audit entries are written automatically as your organization uses DSRclone."
        columns={['Action','Resource','When']}
        renderRow={(item: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[String(item.action ?? ""), String(item.resourceType ?? ""), String(item.createdAt ?? "")]} />
        )}
      />
    </>
  );
}
