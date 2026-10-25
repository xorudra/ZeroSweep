import type { ReactNode } from "react";

/** Shared console primitives — framed-sheet skin (owner-approved
 *  sample, 2026-10-25): white surfaces on the white sheet, separated by
 *  a 1px edge and one tone step, never by shadow. Ink text, muted
 *  secondary text, colour only on data and status. */

export function Card({ title, eyebrow, children }: { title?: string; eyebrow?: string; children: ReactNode }) {
  return (
    <section className="rounded-lg border border-[#e8eaec] bg-white p-5">
      {eyebrow ? <p className="text-[12px] text-[#5d5f60]">{eyebrow}</p> : null}
      {title ? <h3 className="mt-1 text-base font-medium text-[#131416]">{title}</h3> : null}
      <div className="mt-3">{children}</div>
    </section>
  );
}

export function StatCard({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-lg border border-[#e8eaec] bg-white p-5">
      <p className="text-sm font-medium text-[#131416]">{label}</p>
      <p className="mt-2 text-[28px] leading-none text-[#131416] [font-variant-numeric:tabular-nums]">{value}</p>
      {hint ? <p className="mt-1 text-[13px] text-[#5d5f60]">{hint}</p> : null}
    </div>
  );
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-[#ffedea] text-[#831c1e] border-[#f5c6c0]",
  HIGH: "bg-[#ffedd5] text-[#7c2d12] border-[#fed7aa]",
  MEDIUM: "bg-[#fffbeb] text-[#92400e] border-[#fde68a]",
  LOW: "bg-[#e0f2fe] text-[#0c4a6e] border-[#bae6fd]",
  INFORMATIONAL: "bg-[#ebedee] text-[#353736] border-[#e8eaec]",
  VERIFIED: "bg-[#dcfae5] text-[#04250e] border-[#bbf7d0]",
  PENDING: "bg-[#fffbeb] text-[#92400e] border-[#fde68a]",
};

export function Badge({ children, tone }: { children: ReactNode; tone?: string }) {
  const cls = (tone && SEVERITY_STYLES[tone]) || "bg-[#ebedee] text-[#353736] border-[#e8eaec]";
  return <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${cls}`}>{children}</span>;
}

/** Honest empty state — used instead of inventing data that does not exist. */
export function EmptyState({ title, body, action }: { title: string; body: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-[#e8eaec] bg-white px-6 py-12 text-center">
      <p className="text-sm font-medium text-[#131416]">{title}</p>
      <p className="mt-1 max-w-md text-sm text-[#5d5f60]">{body}</p>
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}

export function PrimaryButton({ children, href }: { children: ReactNode; href?: string }) {
  const cls = "inline-flex items-center rounded-lg bg-[#131416] px-4 py-2 text-sm font-medium text-white hover:bg-black";
  if (href) return <a className={cls} href={href}>{children}</a>;
  return <button className={cls} type="button">{children}</button>;
}
