import type { ReactNode } from "react";

/**
 * Shared primitives — "True-black flat" system (taste-skill app sheet,
 * 2026-10-23). Surfaces separate by lightness step alone (#111 on
 * #000), never by border + shadow. No mono uppercase kickers: labels
 * are sentence case at a readable size. The `eyebrow` prop is still
 * accepted for compatibility with existing call sites but is no
 * longer rendered as a kicker; it becomes the heading only when a
 * card has no title of its own.
 */
export function Card({ title, eyebrow, children }: { title?: string; eyebrow?: string; children: ReactNode }) {
  const heading = title ?? eyebrow;
  return (
    <section className="rounded-xl bg-slate-900 p-5">
      {heading ? <h3 className="text-base font-medium text-slate-50">{heading}</h3> : null}
      <div className={heading ? "mt-3" : ""}>{children}</div>
    </section>
  );
}

export function StatCard({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-xl bg-slate-900 p-5">
      <p className="text-xs text-slate-400">{label}</p>
      <p className="tnum mt-1.5 text-2xl font-medium text-slate-50">{value}</p>
      {hint ? <p className="mt-1 text-xs text-slate-400">{hint}</p> : null}
    </div>
  );
}

/* Status pills: a pale tint of the hue with ink of the same hue, no
   border, never a saturated fill (sheet §status pairs, dark). */
const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-[#2c1a20] text-[#e5566f]",
  HIGH: "bg-[#2e1d16] text-[#f0883e]",
  MEDIUM: "bg-[#2b2414] text-[#e5a93b]",
  LOW: "bg-[#12242e] text-[#4cb3f0]",
  INFORMATIONAL: "bg-[#222222] text-[#e6e6e6]",
  VERIFIED: "bg-[#172a1d] text-[#3fc07a]",
  PENDING: "bg-[#2b2414] text-[#e5a93b]",
};

export function Badge({ children, tone }: { children: ReactNode; tone?: string }) {
  const cls = (tone && SEVERITY_STYLES[tone]) || "bg-[#222222] text-[#e6e6e6]";
  return <span className={`inline-flex items-center whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium ${cls}`}>{children}</span>;
}

/** Honest empty state — used instead of inventing data that does not exist. */
export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-700 px-6 py-12 text-center">
      <p className="text-sm font-medium text-slate-100">{title}</p>
      <p className="mt-1 max-w-md text-sm text-slate-400">{body}</p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

/** The one primary action: inverted white pill, black text (sheet move). */
export function PrimaryButton({ children, href }: { children: ReactNode; href?: string }) {
  const cls = "inline-flex h-9 items-center rounded-full bg-white px-4 text-sm font-medium text-black transition-colors hover:bg-slate-200";
  if (href) return <a className={cls} href={href}>{children}</a>;
  return <button className={cls} type="button">{children}</button>;
}
