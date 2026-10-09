"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { apiFetch, ApiError } from "@/lib/api-client";

/**
 * Admin dashboard (owner-selected dark admin design): greeting header,
 * four stat cards with honest period deltas, a 14-day activity chart,
 * findings-by-severity and live system status, and the recent-users
 * table. Every value comes from GET /platform/dashboard — real row
 * counts and live health checks only; empty states say so.
 */

interface WindowStat { cur: number; prev: number; deltaPct: number | null; }
interface RecentUser { id: string; name: string; email: string; organization: string | null; role: string | null; status: string; isPlatformAdmin: boolean; createdAt: string; lastLoginAt: string | null; }
interface Dashboard {
  generatedAt: string;
  counts: { organizations: number; users: number; workspaces: number; targets: number; scans: number; findings: number };
  windows: { users: WindowStat; scans: WindowStat; findings: WindowStat; organizations: WindowStat };
  series14d: { days: string[]; scans: number[]; findings: number[] };
  findingsBySeverity: Array<{ severity: string; count: number }>;
  scansByStatus: Record<string, number>;
  recentUsers: RecentUser[];
  health: { status: string; checks: Record<string, { status: string; detail?: string }> };
}
interface Me { name?: string; email?: string; }

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#FF5C7A", HIGH: "#FF9F43", MEDIUM: "#F5C542", LOW: "#57C7FF", INFO: "#6E779A",
};
const CHECK_LABELS: Record<string, string> = {
  api: "API", postgres: "Database", redis: "Queue / Redis", minio: "Object storage", ai: "AI copilot service", worker: "Worker (background jobs)", web: "Web console",
};

function DeltaPill({ w }: { w: WindowStat }) {
  if (w.deltaPct === null) return <span className="rounded-full bg-[#232E57] px-2 py-0.5 text-[11px] text-[#AEB4D1]">no baseline</span>;
  const up = w.deltaPct >= 0;
  return (
    <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${up ? "bg-[#2FD673]/15 text-[#2FD673]" : "bg-[#FF5C7A]/15 text-[#FF5C7A]"}`}>
      {up ? "↗" : "↘"} {Math.abs(w.deltaPct)}%
    </span>
  );
}

function StatCard({ label, value, sub, window, accent }: { label: string; value: number; sub: string; window: WindowStat; accent: string }) {
  return (
    <div className="rounded-xl border border-[#232E57] bg-[#131A38] p-5">
      <div className="flex items-center justify-between">
        <p className="flex items-center gap-2 text-[13px] text-[#AEB4D1]">
          <span className="inline-block h-2.5 w-2.5 rounded-[4px]" style={{ background: accent }} /> {label}
        </p>
        <span className="text-[#6E779A]">•••</span>
      </div>
      <p className="mt-3 text-[26px] font-bold leading-none text-white">{value.toLocaleString()}</p>
      <div className="mt-3 flex items-center gap-2">
        <DeltaPill w={window} />
        <span className="text-[11px] text-[#6E779A]">{sub}</span>
      </div>
    </div>
  );
}

function ActivityChart({ days, scans, findings }: Dashboard["series14d"]) {
  const W = 720, H = 220, PAD = 28;
  const max = Math.max(1, ...scans, ...findings);
  const x = (i: number) => PAD + (i * (W - PAD * 2)) / Math.max(1, days.length - 1);
  const y = (v: number) => H - PAD - (v / max) * (H - PAD * 2);
  const line = (vals: number[]) => vals.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = (vals: number[]) => `${line(vals)} L${x(vals.length - 1).toFixed(1)},${H - PAD} L${x(0).toFixed(1)},${H - PAD} Z`;
  const total = (a: number[]) => a.reduce((s, v) => s + v, 0);
  return (
    <div className="rounded-xl border border-[#232E57] bg-[#131A38] p-5 lg:col-span-2">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[15px] font-semibold text-white">Platform activity</p>
          <p className="mt-1 text-[12px] text-[#6E779A]">Scans and findings recorded per day — last 14 days, real rows only.</p>
        </div>
        <div className="flex items-center gap-4 text-[12px] text-[#AEB4D1]">
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-[#CB3CFF]" /> Scans · {total(scans)}</span>
          <span className="flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-[#57C7FF]" /> Findings · {total(findings)}</span>
        </div>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="mt-4 w-full" role="img" aria-label="Scans and findings over the last 14 days">
        {[0.25, 0.5, 0.75, 1].map((f) => (
          <line key={f} x1={PAD} x2={W - PAD} y1={y(max * f)} y2={y(max * f)} stroke="#232E57" strokeDasharray="3 5" />
        ))}
        <path d={area(scans)} fill="#CB3CFF" opacity="0.14" />
        <path d={line(scans)} fill="none" stroke="#CB3CFF" strokeWidth="2.5" strokeLinejoin="round" />
        <path d={line(findings)} fill="none" stroke="#57C7FF" strokeWidth="2.5" strokeLinejoin="round" />
        {days.map((d, i) => (i % 3 === 0 || i === days.length - 1 ? (
          <text key={d} x={x(i)} y={H - 8} textAnchor="middle" fontSize="10" fill="#6E779A">{d.slice(5)}</text>
        ) : null))}
        <text x={PAD - 6} y={y(max) + 3} textAnchor="end" fontSize="10" fill="#6E779A">{max}</text>
      </svg>
      {total(scans) + total(findings) === 0 ? (
        <p className="mt-2 text-[12px] text-[#6E779A]">No scans or findings in this window yet — the chart will draw itself from real activity.</p>
      ) : null}
    </div>
  );
}

export default function AdminDashboardPage() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    // The API sleeps when idle on the free tier: the first request after
    // a quiet spell can fail while it wakes. Retry with backoff before
    // declaring the plane closed — one failed load used to stick until
    // the page was remounted.
    let cancelled = false;
    const delays = [0, 1500, 3500];
    (async () => {
      for (let i = 0; i < delays.length; i++) {
        if (delays[i]) await new Promise((r) => setTimeout(r, delays[i]));
        if (cancelled) return;
        try {
          const d = await apiFetch<Dashboard>("/platform/dashboard");
          if (!cancelled) { setData(d); setError(null); }
          return;
        } catch (e) {
          if (e instanceof ApiError && e.status === 403) {
            if (!cancelled) setError("Your account does not hold a platform role (OWNER / ADMIN), so the admin plane stays closed.");
            return;
          }
          if (i === delays.length - 1 && !cancelled) {
            setError("The admin data could not be loaded. The API may be waking up — try again in a few seconds.");
          }
        }
      }
    })();
    apiFetch<Me>("/auth/me").then(setMe).catch(() => undefined);
    return () => { cancelled = true; };
  }, [attempt]);

  const firstName = (me?.name ?? "").split(" ")[0] || "Admin";
  const sevTotal = data?.findingsBySeverity.reduce((s, r) => s + r.count, 0) ?? 0;

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-[24px] font-bold text-white">Hello, {firstName}</h1>
          <p className="mt-1 text-[13px] text-[#AEB4D1]">Here&apos;s what&apos;s happening across your platform today.</p>
        </div>
        <div className="flex items-center gap-3">
          <Link href="/admin/platform/queues" className="text-[13px] font-medium text-[#AEB4D1] hover:text-white">↓ Queue health</Link>
          <Link href="/admin/platform" className="rounded-md bg-[#CB3CFF] px-4 py-2 text-[13px] font-semibold text-white hover:bg-[#b62fe8]">Platform Ops</Link>
        </div>
      </div>

      {error ? (
        <div className="mt-6 rounded-xl border border-[#232E57] bg-[#131A38] p-6 text-[14px] text-[#FF9DB1]">
          <p>{error}</p>
          <button onClick={() => { setError(null); setData(null); setAttempt((a) => a + 1); }} className="mt-3 rounded-md bg-[#CB3CFF] px-4 py-2 text-[13px] font-semibold text-white hover:bg-[#b62fe8]">Retry</button>
        </div>
      ) : !data ? (
        <p className="mt-6 text-[13px] text-[#6E779A]">Loading platform data…</p>
      ) : (
        <>
          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Organizations" value={data.counts.organizations} sub="vs prior 7 days" window={data.windows.organizations} accent="#CB3CFF" />
            <StatCard label="Users" value={data.counts.users} sub="vs prior 7 days" window={data.windows.users} accent="#57C7FF" />
            <StatCard label="Scans" value={data.counts.scans} sub="vs prior 7 days" window={data.windows.scans} accent="#6C5CE7" />
            <StatCard label="Findings" value={data.counts.findings} sub="vs prior 7 days" window={data.windows.findings} accent="#2FD673" />
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
            <ActivityChart days={data.series14d.days} scans={data.series14d.scans} findings={data.series14d.findings} />
            <div className="flex flex-col gap-4">
              <div className="rounded-xl border border-[#232E57] bg-[#131A38] p-5">
                <p className="text-[15px] font-semibold text-white">Findings by severity</p>
                <div className="mt-4 space-y-3">
                  {data.findingsBySeverity.length === 0 ? (
                    <p className="text-[12px] text-[#6E779A]">No findings recorded yet.</p>
                  ) : data.findingsBySeverity.map((r) => (
                    <div key={r.severity}>
                      <div className="flex items-center justify-between text-[12px]">
                        <span className="text-[#AEB4D1]">{r.severity}</span>
                        <span className="font-semibold text-white">{r.count}</span>
                      </div>
                      <div className="mt-1 h-2 rounded-full bg-[#232E57]">
                        <div className="h-2 rounded-full" style={{ width: `${sevTotal ? Math.max(4, (r.count / sevTotal) * 100) : 0}%`, background: SEVERITY_COLORS[r.severity] ?? "#6E779A" }} />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="rounded-xl border border-[#232E57] bg-[#131A38] p-5">
                <div className="flex items-center justify-between">
                  <p className="text-[15px] font-semibold text-white">System status</p>
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${data.health.status === "ok" ? "bg-[#2FD673]/15 text-[#2FD673]" : "bg-[#F5C542]/15 text-[#F5C542]"}`}>
                    {data.health.status}
                  </span>
                </div>
                <ul className="mt-3 space-y-2">
                  {Object.entries(data.health.checks).map(([key, c]) => (
                    <li key={key} className="flex items-center justify-between text-[13px]">
                      <span className="flex items-center gap-2 text-[#AEB4D1]">
                        <span className={`h-2 w-2 rounded-full ${c.status === "ok" ? "bg-[#2FD673]" : "bg-[#FF5C7A]"}`} />
                        {CHECK_LABELS[key] ?? key}
                      </span>
                      <span className={c.status === "ok" ? "text-[#2FD673]" : "text-[#FF5C7A]"}>{c.status}{c.detail ? ` — ${c.detail}` : ""}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-3 text-[11px] text-[#6E779A]">Every service, checked live · {new Date(data.generatedAt).toLocaleTimeString()}</p>
              </div>
            </div>
          </div>

          <div className="mt-4 overflow-hidden rounded-xl border border-[#232E57] bg-[#131A38]">
            <div className="flex items-center justify-between p-5 pb-3">
              <p className="text-[15px] font-semibold text-white">Recent users</p>
              <span className="text-[12px] text-[#6E779A]">{data.counts.users} total</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-left text-[13px]">
                <thead>
                  <tr className="border-y border-[#232E57] text-[11px] uppercase tracking-wide text-[#6E779A]">
                    <th className="px-5 py-3 font-medium">User</th>
                    <th className="px-5 py-3 font-medium">Organization</th>
                    <th className="px-5 py-3 font-medium">Role</th>
                    <th className="px-5 py-3 font-medium">Status</th>
                    <th className="px-5 py-3 font-medium">Last sign-in</th>
                    <th className="px-5 py-3 font-medium">Joined</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recentUsers.map((u) => (
                    <tr key={u.id} className="border-b border-[#1B2447] last:border-0 hover:bg-[#171F42]">
                      <td className="px-5 py-3">
                        <span className="flex items-center gap-3">
                          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[#6C5CE7] text-[12px] font-bold text-white">
                            {(u.name || u.email).slice(0, 2).toUpperCase()}
                          </span>
                          <span>
                            <span className="block font-medium text-white">{u.name}</span>
                            <span className="block text-[12px] text-[#6E779A]">{u.email}</span>
                          </span>
                        </span>
                      </td>
                      <td className="px-5 py-3 text-[#AEB4D1]">{u.organization ?? "—"}</td>
                      <td className="px-5 py-3">
                        <span className="rounded-full bg-[#232E57] px-2 py-0.5 text-[11px] font-medium text-[#C9CFEA]">{u.role ?? "—"}</span>
                        {u.isPlatformAdmin ? <span className="ml-2 rounded-full bg-[#CB3CFF]/15 px-2 py-0.5 text-[11px] font-semibold text-[#E9B8FF]">PLATFORM ADMIN</span> : null}
                      </td>
                      <td className="px-5 py-3">
                        <span className="flex items-center gap-1.5 text-[#AEB4D1]">
                          <span className={`h-2 w-2 rounded-full ${u.status === "ACTIVE" ? "bg-[#2FD673]" : "bg-[#6E779A]"}`} /> {u.status}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-[#AEB4D1]">{u.lastLoginAt ? new Date(u.lastLoginAt).toLocaleDateString() : "Never"}</td>
                      <td className="px-5 py-3 text-[#AEB4D1]">{new Date(u.createdAt).toLocaleDateString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
