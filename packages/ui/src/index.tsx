import type { ReactNode } from "react";

export function Card({ title, eyebrow, children }: { title?: string; eyebrow?: string; children: ReactNode }) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      {eyebrow ? <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400">{eyebrow}</p> : null}
      {title ? <h3 className="mt-1 text-base font-semibold text-slate-100">{title}</h3> : null}
      <div className="mt-3">{children}</div>
    </section>
  );
}

export function StatCard({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <p className="font-mono text-[11px] uppercase tracking-widest text-slate-400">{label}</p>
      <p className="mt-2 text-3xl font-bold text-slate-50">{value}</p>
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-500/15 text-red-300 border-red-500/40",
  HIGH: "bg-orange-500/15 text-orange-300 border-orange-500/40",
  MEDIUM: "bg-yellow-500/15 text-yellow-200 border-yellow-500/40",
  LOW: "bg-sky-500/15 text-sky-300 border-sky-500/40",
  INFORMATIONAL: "bg-slate-500/15 text-slate-300 border-slate-500/40",
  VERIFIED: "bg-emerald-500/15 text-emerald-300 border-emerald-500/40",
  PENDING: "bg-yellow-500/15 text-yellow-200 border-yellow-500/40",
};

export function Badge({ children, tone }: { children: ReactNode; tone?: string }) {
  const cls = (tone && SEVERITY_STYLES[tone]) || "bg-slate-500/15 text-slate-300 border-slate-500/40";
  return <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${cls}`}>{children}</span>;
}

/** Honest empty state — used instead of inventing data that does not exist. */
export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-700 bg-slate-900/40 px-6 py-12 text-center">
      <p className="text-sm font-semibold text-slate-200">{title}</p>
      <p className="mt-1 max-w-md text-sm text-slate-400">{body}</p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function PrimaryButton({ children, href }: { children: ReactNode; href?: string }) {
  const cls = "inline-flex items-center rounded-lg bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-cyan-400";
  if (href) return <a className={cls} href={href}>{children}</a>;
  return <button className={cls} type="button">{children}</button>;
}
