import { Card, EmptyState, StatCard } from "@dsrclone/ui";
import { PageHeader } from "@/components/Shell";
import { FindingsOverview } from "@/components/FindingsOverview";

/**
 * Overview. The findings section (Prompt 7 §44) is wired to real persisted
 * findings; the remaining foundation cards still show honest empty states
 * instead of numbers that do not exist. Nothing here is fabricated.
 */
export default function OverviewPage() {
  return (
    <>
      <PageHeader eyebrow="Overview" title="Security posture at a glance"
        body="Assets, scans and findings from your verified targets. Findings below come only from real, authorized scans — the safe vulnerability detection stage (Prompt 7) is live in WEB_BASELINE and WEB_COMPREHENSIVE profiles." />
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Total Assets" value="—" hint="No assets discovered yet" />
        <StatCard label="Active Scans" value="—" hint="No scans running" />
        <StatCard label="Critical Findings" value="—" hint="No findings recorded" />
        <StatCard label="High Findings" value="—" hint="No findings recorded" />
        <StatCard label="Medium Findings" value="—" hint="No findings recorded" />
        <StatCard label="Low Findings" value="—" hint="No findings recorded" />
        <StatCard label="Risk Score" value="—" hint="Calculated after the first scan" />
        <StatCard label="Tool / Worker Health" value="—" hint="See Tools page" />
      </div>
      <div className="mt-6">
        <FindingsOverview />
      </div>
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card eyebrow="Recent" title="Recently discovered assets">
          <EmptyState title="No assets yet" body="Add a target, verify ownership, define scope and run an approved assessment. Discovered assets will appear here." />
        </Card>
        <Card eyebrow="Recent" title="Recent findings">
          <EmptyState title="See the findings overview above" body="Findings come only from real, authorized scans — DSRclone never shows placeholder vulnerabilities. Open the Findings page for the full filterable dashboard." />
        </Card>
      </div>
      <div className="mt-6">
        <Card eyebrow="History" title="Scan history">
          <EmptyState title="No scans yet" body="Your assessment and scan history will appear here once you start your first approved scan." />
        </Card>
      </div>
    </>
  );
}
