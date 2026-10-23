import Link from "next/link";
import { Card, EmptyState } from "@dsrclone/ui";
import { PageHeader } from "@/components/Shell";
import { FindingsOverview } from "@/components/FindingsOverview";

/**
 * Overview — the guided home. The lead element is the road itself
 * (owner order 2026-10-20: "make it simple and guided"), drawn as one
 * track split into its five steps — the product's signature element
 * in the True-black flat system (2026-10-23). Below it, the findings
 * section is wired to real persisted findings; the remaining cards
 * show honest empty states instead of numbers that do not exist.
 * Nothing here is fabricated.
 */
const STEPS = [
  {
    n: 1, title: "Add a target", href: "/targets", cta: "Add a target",
    body: "The website or app you want checked — only yours, or one you have permission to test. Verify it's yours; nothing scans before that.",
  },
  {
    n: 2, title: "Plan & approve", href: "/assessments", cta: "Plan a check",
    body: "Create the assessment: which target, what to check, how deep. The plan and the permission slip in one — a scan runs only after approval.",
  },
  {
    n: 3, title: "Run the scan", href: "/scans", cta: "See scans",
    body: "Start the approved check and watch its progress. Only safe, approved tests are used — DSRclone never attacks the systems it protects.",
  },
  {
    n: 4, title: "Read findings", href: "/findings", cta: "Read findings",
    body: "Every problem found, most dangerous first. Open one to see the proof, what it means, and how to fix it — or ask the AI Copilot.",
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

      <section className="rounded-xl bg-slate-900">
        <div className="flex flex-wrap items-center gap-3 px-5 pt-5">
          <h2 className="flex-1 text-base font-medium text-white">Follow the road</h2>
          <Link href="/targets" className="inline-flex h-9 items-center rounded-full bg-white px-4 text-sm font-medium text-black transition-colors hover:bg-slate-200">
            Start a security check
          </Link>
        </div>
        <p className="px-5 pt-1.5 text-sm text-slate-300">
          New here? Start at step 1. A scan only runs after the target is verified and the plan is approved — that is what keeps every check legal and safe.
        </p>
        <ol className="mt-4 grid divide-y divide-slate-800 border-t border-slate-800 sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-5 lg:divide-x">
          {STEPS.map((s) => (
            <li key={s.n} className="flex flex-col px-5 py-4">
              <p className="text-xs text-slate-400">Step {s.n}</p>
              <p className="mt-1 text-[15px] font-medium text-white">{s.title}</p>
              <p className="mt-1.5 flex-1 text-[13px] leading-relaxed text-slate-300">{s.body}</p>
              <Link href={s.href} className="mt-3 inline-flex w-fit items-center gap-1.5 text-[13px] font-medium text-white underline-offset-4 transition-colors hover:text-[#4cb3f0] hover:underline">
                {s.cta} <span aria-hidden>→</span>
              </Link>
            </li>
          ))}
        </ol>
      </section>

      <div className="mt-6">
        <FindingsOverview />
      </div>
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <Card title="Recently discovered assets">
          <EmptyState title="No assets yet" body="Add a target, verify ownership, define scope and run an approved assessment. Discovered assets will appear here." />
        </Card>
        <Card title="Recent findings">
          <EmptyState title="See the findings overview above" body="Findings come only from real, authorized scans — DSRclone never shows placeholder vulnerabilities. Open the Findings page for the full filterable dashboard." />
        </Card>
      </div>
      <div className="mt-6">
        <Card title="Scan history">
          <EmptyState title="No scans yet" body="Your assessment and scan history will appear here once you start your first approved scan." />
        </Card>
      </div>
    </>
  );
}
