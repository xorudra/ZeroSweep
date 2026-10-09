"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useMemo, useState, type ReactNode, type SVGProps } from "react";
import { useAuth } from "@/lib/auth";
import { apiFetch, getToken } from "@/lib/api-client";

/**
 * Console shell — sidebar rebuilt to the owner-selected design
 * ("Sidebar Navigation Menu for Dashboard", Andrew Mamontov): a floating
 * rounded glass panel with the profile block at top, grouped nav rows,
 * expandable groups whose children hang on a thin tree connector, an
 * orange CTA card at the bottom, and an edge-straddling circular button
 * that collapses the panel into an icon rail with hover fly-out labels.
 * Colour values are visual matches to the reference render: warm dark
 * glass, taupe-grey inactive labels, white active rows on translucent
 * white fills, orange #F2994A reserved for the CTA.
 */

type IconProps = SVGProps<SVGSVGElement>;
const ic = (path: ReactNode) => function Icon(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...props}>{path}</svg>
  );
};
const GridIcon = ic(<><rect x="3.5" y="3.5" width="7" height="7" rx="1.8" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.8" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.8" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.8" /></>);
const ClipboardIcon = ic(<><rect x="5" y="4.5" width="14" height="17" rx="2" /><path d="M9 4.5a3 3 0 0 1 6 0" /><path d="M9 12h6M9 16h4" /></>);
const RadarIcon = ic(<><circle cx="12" cy="12" r="8.5" /><circle cx="12" cy="12" r="4.5" /><circle cx="12" cy="12" r="1" fill="currentColor" /><path d="M12 12 17 6" /></>);
const ShieldIcon = ic(<><path d="M12 3.5 5 6v5c0 4.6 3 7.7 7 9.5 4-1.8 7-4.9 7-9.5V6l-7-2.5Z" /><path d="m9.3 12 2 2 3.6-3.8" /></>);
const BugIcon = ic(<><rect x="7" y="8" width="10" height="11" rx="4.5" /><path d="M12 8V5M8.5 5.5 7 3.8M15.5 5.5 17 3.8M7 13H3.8M7 17H4.5M17 13h3.2M17 17h2.5" /></>);
const SparkIcon = ic(<><path d="M12 4c.6 3.8 1.9 5.4 6 6-4.1.6-5.4 2.2-6 6-.6-3.8-1.9-5.4-6-6 4.1-.6 5.4-2.2 6-6Z" /><path d="M18.8 15.5c.3 1.8.9 2.6 2.7 2.9-1.8.3-2.4 1.1-2.7 2.9-.3-1.8-.9-2.6-2.7-2.9 1.8-.3 2.4-1.1 2.7-2.9Z" /></>);
const PulseIcon = ic(<><path d="M3 12.5h4l2.2-6 4.3 11 2.3-5H21" /></>);
const ScaleIcon = ic(<><path d="M12 4v16M6.5 20h11M12 6.5 6 7m6-.5 6 .5" /><path d="m3.8 13.5 2.2-6 2.2 6a3.4 3.4 0 0 1-4.4 0ZM15.8 13.5l2.2-6 2.2 6a3.4 3.4 0 0 1-4.4 0Z" /></>);
const SlidersIcon = ic(<><path d="M5 7h6M15 7h4M5 12h2M11 12h8M5 17h10M19 17h0" /><circle cx="13" cy="7" r="2" /><circle cx="9" cy="12" r="2" /><circle cx="17" cy="17" r="2" /></>);
const DiamondIcon = ic(<><path d="M12 3.8 20 12l-8 8.2L4 12l8-8.2Z" /><path d="M4 12h16M12 3.8 8.8 12l3.2 8.2L15.2 12 12 3.8Z" /></>);
const LogoutIcon = ic(<><path d="M14 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7" /><path d="M10 12h11M18 8.5 21.5 12 18 15.5" /></>);

interface NavItem { href: string; label: string; }
interface NavGroup { label: string; icon: (props: IconProps) => JSX.Element; items: NavItem[]; }

const GROUPS: NavGroup[] = [
  {
    label: "Assessments", icon: ClipboardIcon, items: [
      { href: "/assessments", label: "Assessments" }, { href: "/scans", label: "Scans" },
      { href: "/findings", label: "Findings" }, { href: "/security-validation", label: "Security Validation" },
      { href: "/reports", label: "Reports" }, { href: "/security-reports", label: "Security Reports" },
    ],
  },
  {
    label: "Attack Surface", icon: RadarIcon, items: [
      { href: "/targets", label: "Targets" }, { href: "/assets", label: "Assets" },
      { href: "/endpoints", label: "Endpoints" }, { href: "/web-surface", label: "Web Surface" },
      { href: "/easm", label: "EASM" }, { href: "/easm/assets", label: "External Assets" },
      { href: "/easm/unknown-assets", label: "Unknown Assets" }, { href: "/easm/discovery", label: "EASM Discovery" },
      { href: "/easm/drift", label: "Exposure Drift" }, { href: "/easm/technologies", label: "Technologies" },
      { href: "/easm/certificates", label: "Certificates" },
    ],
  },
  {
    label: "Security Domains", icon: ShieldIcon, items: [
      { href: "/api-security", label: "API Security" }, { href: "/network", label: "Network" },
      { href: "/code-security", label: "Code Security" }, { href: "/containers", label: "Containers" },
      { href: "/container-security", label: "Container Security" }, { href: "/kubernetes", label: "Kubernetes" },
      { href: "/kubernetes-security", label: "Kubernetes Security" }, { href: "/cloud-security", label: "Cloud Security" },
      { href: "/cloud-security/advanced", label: "Cloud Security V2" }, { href: "/active-directory", label: "Active Directory" },
      { href: "/mobile-security", label: "Mobile Security" }, { href: "/binary-security", label: "Binary Security" },
      { href: "/wireless-security", label: "Wireless Security" }, { href: "/runtime-events", label: "Runtime Events" },
      { href: "/vapt/web", label: "Web VAPT V2" }, { href: "/vapt/api", label: "API VAPT V2" },
      { href: "/vapt/network", label: "Network VAPT V2" },
    ],
  },
  {
    label: "Vulnerabilities", icon: BugIcon, items: [
      { href: "/vulnerabilities", label: "Vulnerabilities" }, { href: "/vulnerabilities/intelligence", label: "Vuln Intelligence" },
      { href: "/vulnerabilities/remediation", label: "Remediation Queue" }, { href: "/vulnerabilities/kev", label: "KEV Console" },
      { href: "/vulnerabilities/epss", label: "EPSS Console" }, { href: "/vulnerabilities/patches", label: "Patch Intelligence" },
      { href: "/software/sbom", label: "SBOM Explorer" }, { href: "/remediation", label: "Remediation" },
      { href: "/remediation/tickets", label: "Remediation Tickets" },
    ],
  },
  {
    label: "AI", icon: SparkIcon, items: [
      { href: "/ai", label: "AI Copilot" }, { href: "/ai/copilot", label: "Copilot Chat" },
      { href: "/ai-security", label: "AI Security V2" }, { href: "/ai-security/copilot", label: "Copilot V2" },
      { href: "/ai-security/plans", label: "AI Plans" }, { href: "/ai-security/approvals", label: "AI Approvals" },
    ],
  },
  {
    label: "Operations", icon: PulseIcon, items: [
      { href: "/soc", label: "SOC" }, { href: "/soc/alerts", label: "SOC Alerts" },
      { href: "/soc/incidents", label: "Incidents" }, { href: "/soc/detections", label: "Detections" },
      { href: "/soc/threat-intelligence", label: "Threat Intel" }, { href: "/analytics", label: "Analytics" },
      { href: "/analytics/attack-surface", label: "Attack Surface Intel" }, { href: "/analytics/vulnerabilities", label: "Vuln Analytics" },
      { href: "/analytics/soc", label: "SOC Analytics" }, { href: "/search", label: "Security Search" },
      { href: "/continuous-security", label: "Continuous Security" }, { href: "/automation/workflows", label: "Workflows" },
      { href: "/notifications", label: "Notifications" }, { href: "/dashboard/executive", label: "Executive Dashboard" },
      { href: "/dashboard/security", label: "Security Dashboard" }, { href: "/dashboard/remediation", label: "Remediation Dashboard" },
      { href: "/dashboard/assets", label: "Asset Risk" },
    ],
  },
  {
    label: "Governance", icon: ScaleIcon, items: [
      { href: "/compliance", label: "Compliance" }, { href: "/grc", label: "GRC" },
      { href: "/grc/controls", label: "GRC Controls" }, { href: "/grc/risks", label: "Risk Register" },
      { href: "/grc/audits", label: "Audits" }, { href: "/grc/evidence", label: "Evidence" },
      { href: "/audit-logs", label: "Audit Logs" },
    ],
  },
  {
    label: "Platform", icon: SlidersIcon, items: [
      { href: "/tools", label: "Tools" }, { href: "/integrations", label: "Integrations" },
      { href: "/devsecops", label: "DevSecOps" }, { href: "/onboarding", label: "Onboarding" },
      { href: "/settings/usage", label: "Usage" }, { href: "/settings/plan", label: "Plan & Entitlements" },
      { href: "/settings/billing", label: "Billing" }, { href: "/settings/license", label: "License" },
      { href: "/status", label: "Status" }, { href: "/settings", label: "Settings" },
    ],
  },
];

const isActive = (pathname: string, href: string) =>
  href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);

interface MeInfo { name?: string; role?: string; isPlatformAdmin?: boolean; }

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { logout } = useAuth();
  const [me, setMe] = useState<MeInfo | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  // Rail fly-out: rendered position:fixed because the scrolling nav would
  // otherwise clip an absolutely-positioned label (and grow a stray
  // horizontal scrollbar). Position is measured from the hovered row.
  const [fly, setFly] = useState<{ label: string; top: number } | null>(null);
  const flyProps = (label: string) => collapsed ? {
    onMouseEnter: (e: React.MouseEvent<HTMLElement>) => {
      const r = e.currentTarget.getBoundingClientRect();
      setFly({ label, top: r.top + r.height / 2 });
    },
    onMouseLeave: () => setFly(null),
  } : {};

  useEffect(() => {
    if (pathname === "/login" || !getToken()) return;
    let cancelled = false;
    apiFetch<MeInfo>("/auth/me").then((m) => { if (!cancelled) setMe(m); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [pathname]);

  useEffect(() => { setCollapsed(window.localStorage.getItem("dsr-sidebar") === "rail"); }, []);
  useEffect(() => {
    const group = GROUPS.find((g) => g.items.some((i) => isActive(pathname, i.href)));
    if (group) setOpen((o) => ({ ...o, [group.label]: true }));
  }, [pathname]);

  const flatNav = useMemo(() => [{ href: "/", label: "Overview" }, ...GROUPS.flatMap((g) => g.items)], []);
  if (pathname === "/login") return <>{children}</>;
  const canAdmin = Boolean(me?.isPlatformAdmin) || me?.role === "OWNER" || me?.role === "ADMIN";
  const initials = (me?.name ?? "Rudra Singh").split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase();
  const toggleRail = () => {
    setCollapsed((c) => { window.localStorage.setItem("dsr-sidebar", c ? "full" : "rail"); return !c; });
  };

  const rowBase = "group relative flex items-center gap-3 rounded-[11px] px-3 text-[13px] transition-colors";
  const rowSize = collapsed ? "h-10 justify-center px-0" : "h-10";

  return (
    <div className="flex min-h-screen bg-slate-950">
      <div className="hidden shrink-0 p-3 pr-0 md:block">
        <aside
          className={`sticky top-3 flex h-[calc(100vh-24px)] flex-col rounded-[22px] border border-white/[0.07] bg-[rgba(34,23,17,0.94)] shadow-[0_24px_60px_rgba(0,0,0,0.55)] backdrop-blur transition-[width] duration-300 ${collapsed ? "w-[80px]" : "w-[250px]"}`}
        >
          <button type="button" onClick={toggleRail} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="absolute -right-3 top-[68px] z-20 flex h-[26px] w-[26px] items-center justify-center rounded-full border border-white/10 bg-[#2B1B13] text-white shadow-lg transition-transform hover:scale-105">
            <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" className={`transition-transform duration-300 ${collapsed ? "rotate-180" : ""}`}><path d="m14.5 5.5-6.5 6.5 6.5 6.5" /></svg>
          </button>

          <div className={`flex items-center gap-3 px-4 pb-2 pt-5 ${collapsed ? "justify-center px-0" : ""}`}>
            <span className="flex h-[38px] w-[38px] shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[#F2994A] to-[#B3541E] text-[13px] font-bold text-white" title={me?.name ?? ""}>
              {initials}
            </span>
            {!collapsed ? (
              <span className="min-w-0">
                <span className="block truncate text-[9px] font-semibold uppercase tracking-[0.16em] text-[#9A887B]">
                  {me?.isPlatformAdmin ? "Platform Admin" : me?.role ?? "Member"}
                </span>
                <span className="block truncate text-[13px] font-semibold leading-tight text-white">{me?.name ?? "…"}</span>
              </span>
            ) : null}
          </div>
          {!collapsed ? <p className="px-4 pb-1 text-[10px] font-medium uppercase tracking-[0.2em] text-[#6E5B4D]">DSRclone Console</p> : null}

          <nav className="mt-1 flex-1 space-y-1 overflow-y-auto overflow-x-hidden px-3 pb-2 [scrollbar-width:thin]">
            <Link href="/" {...flyProps("Overview")} className={`${rowBase} ${rowSize} ${isActive(pathname, "/") ? "bg-white/[0.13] font-semibold text-white" : "text-[#B3A397] hover:bg-white/[0.07] hover:text-white"}`}>
              <GridIcon className="shrink-0" />{!collapsed ? <span>Overview</span> : null}
            </Link>

            {GROUPS.map((group) => {
              const GroupIcon = group.icon;
              const expanded = !collapsed && Boolean(open[group.label]);
              const groupActive = group.items.some((i) => isActive(pathname, i.href));
              return (
                <div key={group.label}>
                  <button type="button" {...flyProps(group.label)}
                    onClick={() => { if (collapsed) { toggleRail(); setOpen((o) => ({ ...o, [group.label]: true })); } else setOpen((o) => ({ ...o, [group.label]: !o[group.label] })); }}
                    className={`${rowBase} ${rowSize} w-full text-left ${groupActive || expanded ? "bg-white/[0.07] text-white" : "text-[#B3A397] hover:bg-white/[0.07] hover:text-white"}`}>
                    <GroupIcon className="shrink-0" />
                    {!collapsed ? <span className="flex-1">{group.label}</span> : null}
                    {!collapsed ? (
                      <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" className={`shrink-0 transition-transform duration-300 ${expanded ? "" : "rotate-180"}`}><path d="m6 14.5 6-6 6 6" /></svg>
                    ) : null}
                  </button>
                  {expanded ? (
                    <div className="relative mb-1 ml-[26px] space-y-0.5 border-l border-white/[0.16] pl-4 pt-1">
                      {group.items.map((item) => (
                        <Link key={item.href} href={item.href}
                          className={`relative block rounded-lg px-2.5 py-[7px] text-[12.5px] transition-colors ${isActive(pathname, item.href) ? "bg-white/[0.14] font-semibold text-white" : "text-[#B3A397] hover:bg-white/[0.07] hover:text-white"}`}>
                          <span className="absolute -left-4 top-1/2 h-px w-3 bg-white/[0.16]" />
                          {item.label}
                        </Link>
                      ))}
                    </div>
                  ) : null}
                </div>
              );
            })}

            {canAdmin ? (
              <Link href="/admin" {...flyProps("Admin Panel")} className={`${rowBase} ${rowSize} ${pathname.startsWith("/admin") ? "bg-[#CB3CFF]/20 font-semibold text-[#F3D1FF]" : "font-medium text-[#E3B7F5] hover:bg-[#CB3CFF]/10"}`}>
                <DiamondIcon className="shrink-0" />{!collapsed ? <span>Admin Panel</span> : null}
              </Link>
            ) : null}
          </nav>

          {collapsed ? (
            <Link href="/assessments" title="New Assessment" {...flyProps("New Assessment")}
              className="mx-auto mb-2 flex h-11 w-11 items-center justify-center rounded-xl bg-[#F2994A] text-[20px] font-semibold text-white transition-transform hover:scale-105">
              +
            </Link>
          ) : (
            <div className="mx-3 mb-2 rounded-2xl bg-white/[0.05] p-4 text-center">
              <p className="text-[13px] font-bold text-white">Ready when you are</p>
              <p className="mt-1 text-[11px] leading-snug text-[#9A887B]">Run a new assessment against a verified target.</p>
              <Link href="/assessments" className="mt-3 block rounded-[10px] bg-[#F2994A] py-2 text-[12.5px] font-semibold text-white transition-colors hover:bg-[#F08A24]">
                + New Assessment
              </Link>
            </div>
          )}

          <button type="button" onClick={logout} {...flyProps("Sign out")}
            className={`group relative mx-3 mb-4 flex items-center gap-3 rounded-[11px] px-3 py-2 text-[12.5px] text-[#9A887B] transition-colors hover:bg-white/[0.07] hover:text-white ${collapsed ? "justify-center px-0" : ""}`}>
            <LogoutIcon className="shrink-0" />{!collapsed ? <span>Sign out</span> : null}
          </button>
          {collapsed && fly ? (
            <span className="pointer-events-none fixed z-50 -translate-y-1/2 whitespace-nowrap rounded-lg border border-white/10 bg-[#2B1B13] px-3 py-1.5 text-[12px] font-medium text-white shadow-xl" style={{ left: 106, top: fly.top }}>
              {fly.label}
            </span>
          ) : null}
        </aside>
      </div>

      <div className="min-w-0 flex-1">
        <header className="border-b border-white/[0.06] bg-[#17100C] px-5 py-3 md:hidden">
          <div className="flex items-center gap-3">
            <span className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-[#F2994A] to-[#B3541E] text-[11px] font-bold text-white">{initials}</span>
            <div>
              <p className="text-[9px] font-semibold uppercase tracking-[0.16em] text-[#9A887B]">{me?.isPlatformAdmin ? "Platform Admin" : me?.role ?? "Member"}</p>
              <p className="text-[13px] font-semibold leading-tight text-white">{me?.name ?? "DSRclone"}</p>
            </div>
          </div>
          <nav className="mt-3 flex flex-wrap gap-2">
            {flatNav.map((item) => (
              <Link key={item.href} href={item.href} className="rounded-full border border-white/10 px-3 py-1 text-xs text-[#CFC2B8]">{item.label}</Link>
            ))}
            {canAdmin ? <Link href="/admin" className="rounded-full border border-[#CB3CFF]/40 px-3 py-1 text-xs text-[#E9B8FF]">Admin Panel</Link> : null}
          </nav>
        </header>
        <main className="mx-auto max-w-7xl p-5 md:p-8">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({ eyebrow, title, body }: { eyebrow: string; title: string; body?: string }) {
  return (
    <div className="mb-6">
      <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400">{eyebrow}</p>
      <h1 className="mt-1 text-2xl font-bold text-slate-50">{title}</h1>
      {body ? <p className="mt-1 max-w-2xl text-sm text-slate-400">{body}</p> : null}
    </div>
  );
}
