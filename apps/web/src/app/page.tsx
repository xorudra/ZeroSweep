import { Card, EmptyState, StatCard } from "@dsrclone/ui";
import { PageHeader } from "@/components/Shell";

/**
 * Overview — foundation phase. Cards are wired to real data in the next
 * phase; until then they show an honest empty state instead of numbers
 * that do not exist. Nothing here is fabricated.
 */
export default function OverviewPage() {
  return (
    <>
      <PageHeader eyebrow="Overview" title="Security posture at a glance"
        body="Assets, scans and findings from your verified targets. Scanners are integrated in later phases — this foundation contains no scan results yet." />
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
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card eyebrow="Recent" title="Recently discovered assets">
          <EmptyState title="No assets yet" body="Add a target, verify ownership, define scope and run an approved assessment. Discovered assets will appear here." />
        </Card>
        <Card eyebrow="Recent" title="Recent findings">
          <EmptyState title="No findings yet" body="Findings come only from real, authorized scans — DSRclone never shows placeholder vulnerabilities." />
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
