import Link from "next/link";
import { Card, EmptyState, StatCard } from "@dsrclone/ui";
import { PageHeader } from "@/components/Shell";
import { FindingsOverview } from "@/components/FindingsOverview";

/**
 * Overview — the guided home. The top card is the whole product in five
 * steps, in order (owner order 2026-10-20: "make it simple and
 * guided"): a new user should never have to guess what to do next.
 * Below it, the findings section (Prompt 7 §44) is wired to real
 * persisted findings; the remaining foundation cards still show honest
 * empty states instead of numbers that do not exist. Nothing here is
 * fabricated.
 */
const STEPS = [
  {
    n: 1, title: "Add a target", href: "/targets", cta: "Add a target",
    body: "The website or app you want checked — only yours, or one you have permission to test. Verify it's yours and choose exactly what may be checked; nothing scans before that.",
  },
  {
    n: 2, title: "Plan & approve", href: "/assessments", cta: "Plan a check",
    body: "Create the assessment: which target, what to check, how deep. It is the plan and the permission slip in one — a scan runs only after it is approved.",
  },
  {
    n: 3, title: "Run the scan", href: "/scans", cta: "See scans",
    body: "Start the approved check and watch its progress. Only safe, approved tests are used — DSRclone never attacks the systems it protects.",
  },
  {
    n: 4, title: "Read findings", href: "/findings", cta: "Read findings",
    body: "Every problem found, most dangerous first. Open one to see the proof, what it means, and how to fix it — or ask the AI Copilot to explain it simply.",
  },
  {
    n: 5, title: "Get the report", href: "/reports", cta: "Get the report",
    body: "Download the final report with everything that was checked and found, ready to keep or share.",
  },
];

export default function OverviewPage() {
  return (
    <>
      <PageHeader eyebrow="Overview" title="Your security check-up home"
        body="One road, five steps: add a target, plan the check, run it, read what was found, download the report. Everything else in the menu is advanced tools — you never need them for a normal check." />
      <Card eyebrow="How DSRclone works" title="Follow the road">
        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {STEPS.map((s) => (
            <li key={s.n} className="flex flex-col rounded-lg border border-slate-800 bg-slate-950/50 p-4">
              <p className="text-sm font-semibold text-slate-100">
                <span className="mr-2 inline-flex h-6 w-6 items-center justify-center rounded-full bg-cyan-400/15 font-mono text-[12px] text-cyan-300">{s.n}</span>
                {s.title}
              </p>
              <p className="mt-2 flex-1 text-[13px] leading-relaxed text-slate-400">{s.body}</p>
              <Link href={s.href} className="mt-3 inline-flex w-fit items-center gap-1.5 rounded-lg bg-[#262626] px-3 py-2 text-[13px] font-medium text-white transition-colors hover:bg-[#333333]">
                {s.cta} <span aria-hidden>→</span>
              </Link>
            </li>
          ))}
          <li className="flex flex-col justify-center rounded-lg border border-dashed border-slate-700 p-4">
            <p className="text-sm font-semibold text-slate-100">New here?</p>
            <p className="mt-2 flex-1 text-[13px] leading-relaxed text-slate-400">Start at step 1. The app will only let a scan run after the target is verified and the plan is approved — that is what keeps every check legal and safe.</p>
            <Link href="/targets" className="mt-3 inline-flex w-fit items-center gap-1.5 rounded-lg bg-white px-3.5 py-2 text-[13px] font-semibold text-[#0F0F0F] transition-colors hover:bg-slate-200">
              Start a security check <span aria-hidden>→</span>
            </Link>
          </li>
        </ol>
      </Card>
      <div className="mt-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
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
