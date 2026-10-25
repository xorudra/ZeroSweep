import Link from "next/link";
import { Card, EmptyState } from "@dsrclone/ui";
import { FindingsOverview } from "@/components/FindingsOverview";

/**
 * Overview — the guided home, framed-sheet skin (owner-approved sample,
 * 2026-10-25). The top strip is the whole product in five steps, in
 * order (owner order 2026-10-20: "make it simple and guided"): a new
 * user should never have to guess what to do next. Below it, the
 * findings section is wired to real persisted findings; the remaining
 * numbers still show honest empty states instead of numbers that do
 * not exist. Nothing here is fabricated.
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

const KPIS = [
  { label: "Total assets", value: "—", hint: "No assets discovered yet" },
  { label: "Active scans", value: "—", hint: "No scans running" },
  { label: "Critical findings", value: "—", hint: "No findings recorded" },
  { label: "High findings", value: "—", hint: "No findings recorded" },
  { label: "Medium findings", value: "—", hint: "No findings recorded" },
  { label: "Low findings", value: "—", hint: "No findings recorded" },
  { label: "Risk score", value: "—", hint: "Calculated after the first scan" },
  { label: "Tool / Worker health", value: "—", hint: "See Tools page" },
];

export default function OverviewPage() {
  return (
    <>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <h1 className="text-[22px] font-semibold leading-tight text-[#131416]">Overview</h1>
        <Link href="/targets" className="ml-auto inline-flex h-8 items-center rounded-lg bg-[#131416] px-4 text-sm font-medium text-white transition-colors hover:bg-black">
          Start a security check
        </Link>
      </div>
      <p className="mt-2 max-w-2xl text-sm text-[#5d5f60]">One road, five steps: add a target, plan the check, run it, read what was found, download the report. Everything else in the menu is advanced tools — you never need them for a normal check.</p>

      <section className="mt-12">
        <div className="mb-4 flex items-baseline justify-between">
          <h2 className="text-base font-medium text-[#131416]">The road</h2>
        </div>
        <div className="grid grid-cols-1 gap-px overflow-hidden rounded-lg border border-[#e8eaec] bg-[#e8eaec] sm:grid-cols-2 lg:grid-cols-5">
          {STEPS.map((s) => (
            <Link key={s.n} href={s.href} className="relative bg-white p-4 pr-9 transition-colors hover:bg-[#f4f6f8]">
              <span aria-hidden className="absolute right-3 top-4 text-[#5d5f60]">→</span>
              <h3 className="text-base font-medium text-[#131416]">{s.title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-[#5d5f60]">{s.body}</p>
            </Link>
          ))}
        </div>
        <p className="mt-3 text-sm text-[#5d5f60]"><span className="font-medium text-[#131416]">New here?</span> Start at step 1. The app will only let a scan run after the target is verified and the plan is approved — that is what keeps every check legal and safe.</p>
      </section>

      <section className="mt-12">
        <div className="mb-4 flex items-baseline justify-between">
          <h2 className="text-base font-medium text-[#131416]">Usage</h2>
        </div>
        <div className="rounded-lg bg-[#fafafa] p-1.5">
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-md border border-[#e8eaec] bg-[#e8eaec] lg:grid-cols-4">
            {KPIS.map((k) => (
              <div key={k.label} className="bg-[#fafafa] p-4">
                <p className="text-sm font-medium text-[#131416]">{k.label}</p>
                <p className="mt-1 text-[28px] leading-none text-[#131416] [font-variant-numeric:tabular-nums]">{k.value}</p>
                <p className="mt-1 text-[13px] text-[#5d5f60]">{k.hint}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="mt-12">
        <FindingsOverview />
      </div>
      <div className="mt-12 grid gap-6 lg:grid-cols-2">
        <Card eyebrow="Recent" title="Recently discovered assets">
          <EmptyState title="No assets yet" body="Add a target, verify ownership, define scope and run an approved assessment. Discovered assets will appear here." />
        </Card>
        <Card eyebrow="Recent" title="Recent findings">
          <EmptyState title="See the findings overview above" body="Findings come only from real, authorized scans — DSRclone never shows placeholder vulnerabilities. Open the Findings page for the full filterable dashboard." />
        </Card>
      </div>
      <div className="mt-12">
        <Card eyebrow="History" title="Scan history">
          <EmptyState title="No scans yet" body="Your assessment and scan history will appear here once you start your first approved scan." />
        </Card>
      </div>
    </>
  );
}
