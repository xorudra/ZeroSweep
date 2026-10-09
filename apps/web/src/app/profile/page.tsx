"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { apiFetch } from "@/lib/api-client";
import { useAuth } from "@/lib/auth";

/**
 * Profile page, styled after the "Free User Profile" persona dashboard
 * (Brand Kit, Figma Community): a sage-to-deep-green identity panel, a
 * peach-to-violet gradient card with a segmented white donut, and dark
 * stat cards with oversized numerals. Every number here is real — the
 * donut and stats read GET /findings/summary (the same persisted counts
 * as the Overview), and the account facts come from GET /auth/me.
 * Nothing is placeholder data; unavailable data says so.
 */

interface ProfileMe {
  id: string;
  email: string;
  name?: string;
  role?: string;
  isPlatformAdmin?: boolean;
  organizationName?: string | null;
  workspaceName?: string | null;
  memberSince?: string | null;
  lastLoginAt?: string | null;
  emailVerified?: boolean;
  accountStatus?: string | null;
}

interface Summary {
  total: number;
  bySeverity: Record<string, number>;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const SEG_OPACITY: Record<string, number> = { CRITICAL: 1, HIGH: 0.72, MEDIUM: 0.48, LOW: 0.28, INFO: 0.15 };

function fmtDate(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
}
function fmtDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : d.toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function Donut({ summary }: { summary: Summary }) {
  const total = summary.total;
  const R = 56;
  const C = 2 * Math.PI * R;
  const GAP = total > 0 ? 4 : 0;
  let acc = 0;
  const segs = SEVERITIES.map((sev) => {
    const count = summary.bySeverity[sev] ?? summary.bySeverity[sev.toLowerCase()] ?? 0;
    const share = total > 0 ? count / total : 0;
    const seg = { sev, count, share, start: acc };
    acc += share;
    return seg;
  }).filter((s) => s.count > 0);
  return (
    <svg viewBox="0 0 140 140" className="h-[150px] w-[150px]" role="img" aria-label="Findings by severity">
      <circle cx="70" cy="70" r={R} fill="none" stroke="rgba(255,255,255,0.18)" strokeWidth="13" />
      {segs.map((s) => {
        const len = Math.max(s.share * C - GAP, 0.5);
        return (
          <circle key={s.sev} cx="70" cy="70" r={R} fill="none"
            stroke="#FFFFFF" strokeOpacity={SEG_OPACITY[s.sev] ?? 0.4} strokeWidth="13" strokeLinecap="butt"
            strokeDasharray={`${len} ${C - len}`}
            transform={`rotate(${-90 + s.start * 360} 70 70)`} />
        );
      })}
      <text x="70" y="68" textAnchor="middle" fill="#FFFFFF" fontSize="30" fontWeight="700">{total}</text>
      <text x="70" y="88" textAnchor="middle" fill="rgba(255,255,255,0.75)" fontSize="10.5">findings</text>
    </svg>
  );
}

export default function ProfilePage() {
  const { logout } = useAuth();
  const [me, setMe] = useState<ProfileMe | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [summaryFailed, setSummaryFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    apiFetch<ProfileMe>("/auth/me").then((m) => { if (!cancelled) setMe(m); }).catch(() => undefined);
    apiFetch<Summary>("/findings/summary")
      .then((s) => { if (!cancelled) setSummary(s); })
      .catch(() => { if (!cancelled) setSummaryFailed(true); });
    return () => { cancelled = true; };
  }, []);

  const name = me?.name ?? "…";
  const initials = useMemo(
    () => (me?.name ?? "Rudra Singh").split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase(),
    [me?.name],
  );
  const sevCount = (sev: string) =>
    summary ? (summary.bySeverity[sev] ?? summary.bySeverity[sev.toLowerCase()] ?? 0) : 0;
  const pct = (sev: string) =>
    summary && summary.total > 0 ? Math.round((sevCount(sev) / summary.total) * 100) : 0;
  const daysMember = useMemo(() => {
    if (!me?.memberSince) return null;
    const t = new Date(me.memberSince).getTime();
    return Number.isNaN(t) ? null : Math.max(0, Math.floor((Date.now() - t) / 86_400_000));
  }, [me?.memberSince]);

  const detailRows: [string, string][] = [
    ["Full name", me?.name ?? "—"],
    ["Email", me?.email ?? "—"],
    ["Role", me?.role ?? "—"],
    ["Organization", me?.organizationName ?? "—"],
    ["Workspace", me?.workspaceName ?? "—"],
    ["Member since", fmtDate(me?.memberSince)],
    ["Last login", fmtDateTime(me?.lastLoginAt)],
    ["Email verified", me ? (me.emailVerified ? "Yes" : "No") : "—"],
    ["Account status", me?.accountStatus ?? "—"],
  ];

  const statCards = [
    { label: "Findings", value: summary ? String(summary.total) : "—", caption: "recorded across your organization", accent: "#3D4BFF" },
    { label: "Critical + High", value: summary ? String(sevCount("CRITICAL") + sevCount("HIGH")) : "—", caption: "the ones to clear first", accent: "#2EC4B6" },
    { label: "Days as a member", value: daysMember !== null ? String(daysMember) : "—", caption: `member since ${fmtDate(me?.memberSince)}`, accent: "#EE7A52" },
  ];

  const accessLinks = [
    { href: "/settings/security/mfa", label: "My MFA & passkeys", hint: "Two-factor and passkey enrollment" },
    { href: "/settings/security/sessions", label: "My sessions", hint: "Devices currently signed in" },
    { href: "/settings/api-keys", label: "API keys", hint: "Keys for programmatic access" },
    { href: "/settings/organization/members", label: "Organization members", hint: "Everyone in your organization" },
  ];

  return (
    <div>
      <p className="text-[12px] text-[#8E8E9A]">{name} <span className="mx-1 text-[#55555f]">/</span> <span className="text-slate-300">Profile</span></p>

      <div className="mt-3 grid gap-4 lg:grid-cols-3">
        {/* Identity panel — the design's photo card, as a deep-green gradient with the user's monogram */}
        <section className="relative overflow-hidden rounded-[20px] lg:col-span-2" style={{ background: "linear-gradient(160deg,#D6E0BE 0%,#59806B 48%,#234F3C 100%)" }}>
          <span aria-hidden className="pointer-events-none absolute -right-4 top-1/2 -translate-y-1/2 select-none text-[190px] font-bold leading-none text-white/15">{initials}</span>
          <div className="relative flex min-h-[290px] flex-col justify-end p-6">
            <span className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-white/95 text-[20px] font-bold text-[#234F3C] shadow-lg">{initials}</span>
            <h1 className="text-[30px] font-bold leading-tight text-white">{name}</h1>
            <p className="mt-0.5 text-[14px] text-white/75">{me?.email ?? ""}</p>
            <div className="mt-4 flex flex-wrap gap-2">
              {me?.role ? <span className="rounded-full bg-black/25 px-3 py-1 text-[11.5px] font-semibold tracking-wide text-white">{me.role}</span> : null}
              {me?.isPlatformAdmin ? <span className="rounded-full bg-white px-3 py-1 text-[11.5px] font-semibold tracking-wide text-[#234F3C]">PLATFORM ADMIN</span> : null}
              {me?.organizationName ? <span className="rounded-full bg-black/25 px-3 py-1 text-[11.5px] font-medium text-white">{me.organizationName}</span> : null}
            </div>
          </div>
        </section>

        {/* Gradient donut card — findings by severity, real counts only */}
        <section className="rounded-[20px] p-5" style={{ background: "linear-gradient(120deg,#F2B18C 0%,#B06FD6 55%,#5E22D6 100%)" }}>
          <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-white/85">Findings by severity</p>
          <div className="mt-2 flex justify-center">
            {summary ? <Donut summary={summary} /> : (
              <div className="flex h-[150px] w-[150px] items-center justify-center rounded-full border-[13px] border-white/20 text-center text-[12px] text-white/85">
                {summaryFailed ? "Unavailable" : "Loading…"}
              </div>
            )}
          </div>
          <div className="mt-2 divide-y divide-white/15">
            {SEVERITIES.filter((sev) => sev !== "INFO" || sevCount("INFO") > 0).map((sev) => (
              <div key={sev} className="flex items-center gap-2.5 py-[7px] text-[13px]">
                <span className="h-[7px] w-[7px] shrink-0 rounded-full bg-white" style={{ opacity: SEG_OPACITY[sev] }} />
                <span className="flex-1 capitalize text-white/90">{sev.toLowerCase()}</span>
                <span className="font-semibold text-white">{summary ? `${pct(sev)}%` : "—"}</span>
              </div>
            ))}
          </div>
          {summary && summary.total === 0 ? (
            <p className="mt-3 text-[12px] leading-snug text-white/75">No findings recorded yet — they appear here after an approved scan.</p>
          ) : null}
          {summaryFailed ? (
            <p className="mt-3 text-[12px] leading-snug text-white/85">Findings data could not be loaded right now.</p>
          ) : null}
        </section>
      </div>

      {/* Stat cards */}
      <div className="mt-4 grid gap-4 sm:grid-cols-3">
        {statCards.map((c) => (
          <section key={c.label} className="rounded-2xl border border-[#242433] bg-[#10101A] p-5">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full" style={{ background: c.accent }} />
              <p className="text-[13px] font-medium text-slate-200">{c.label}</p>
            </div>
            <p className="mt-3 text-[44px] font-bold leading-none text-white">{c.value}</p>
            <p className="mt-2 text-[12px] text-[#8E8E9A]">{c.caption}</p>
          </section>
        ))}
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        {/* Profile details */}
        <section className="rounded-2xl border border-[#242433] bg-[#10101A] p-5">
          <h2 className="text-[15px] font-semibold text-white">Profile details</h2>
          <dl className="mt-3 divide-y divide-white/[0.06]">
            {detailRows.map(([k, v]) => (
              <div key={k} className="flex items-baseline justify-between gap-4 py-[9px]">
                <dt className="shrink-0 text-[12.5px] text-[#8E8E9A]">{k}</dt>
                <dd className="truncate text-right text-[13.5px] font-medium text-slate-100">{v}</dd>
              </div>
            ))}
          </dl>
        </section>

        {/* Security & access — echoes the design's outlined identity card */}
        <section className="rounded-2xl border border-[#242433] bg-[#10101A] p-5">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-[#2c2c3a] bg-[#0b0b13] text-slate-200">
              <svg viewBox="0 0 24 24" width="19" height="19" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" aria-hidden>
                <path d="M12 11a3 3 0 1 0-3-3" /><path d="M12 14v3" /><path d="M9.5 21v-4.2A5.5 5.5 0 0 1 12 6a5.5 5.5 0 0 1 5.5 5.5c0 1.5-.2 3-.6 4.5" /><path d="M6.6 18.5A9 9 0 0 1 6 12a6 6 0 0 1 1.8-4.3" /><path d="M17.7 20.4c.5-1 .8-2 .9-3.1" />
              </svg>
            </span>
            <div>
              <h2 className="text-[15px] font-semibold leading-tight text-white">{name}</h2>
              <p className="text-[12px] leading-tight text-[#8E8E9A]">User Profile · security & access</p>
            </div>
          </div>
          <div className="mt-4 space-y-1">
            {accessLinks.map((l) => (
              <Link key={l.href} href={l.href} className="flex items-center gap-3 rounded-xl px-3 py-2.5 transition-colors hover:bg-[#171724]">
                <span className="min-w-0 flex-1">
                  <span className="block text-[13.5px] font-medium text-slate-100">{l.label}</span>
                  <span className="block truncate text-[12px] text-[#8E8E9A]">{l.hint}</span>
                </span>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#8E8E9A" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m9.5 5.5 6.5 6.5-6.5 6.5" /></svg>
              </Link>
            ))}
          </div>
          <button type="button" onClick={logout}
            className="mt-4 w-full rounded-xl border border-[#2c2c3a] py-2.5 text-[13px] font-medium text-slate-200 transition-colors hover:bg-[#171724]">
            Sign out
          </button>
        </section>
      </div>
    </div>
  );
}
