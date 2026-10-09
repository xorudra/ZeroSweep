"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type ReactNode, type SVGProps } from "react";
import { useAuth } from "@/lib/auth";
import { apiFetch, getToken } from "@/lib/api-client";

/**
 * Console shell — sidebar built to the owner-selected design #3 from
 * "8 Free Sidebar Designs" (Raafi G, CC BY 4.0): a flush full-height
 * near-black panel (#0F0F0F), a workspace switcher box at the top, a
 * search field with a ⌘K badge (live-filters the navigation), flat
 * monochrome menu rows whose active state is a neutral dark-grey pill
 * with white text, and the user profile pinned at the bottom. No accent
 * colour anywhere — the set is deliberately black/white/grey. Our 86
 * destinations sit behind the eight group rows; groups expand in place
 * and the group holding the current page opens automatically.
 */

type IconProps = SVGProps<SVGSVGElement>;
const ic = (path: ReactNode) => function Icon(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...props}>{path}</svg>
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
const SearchIcon = ic(<><circle cx="11" cy="11" r="6.5" /><path d="m16 16 4.5 4.5" /></>);

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

interface MeInfo { name?: string; email?: string; role?: string; isPlatformAdmin?: boolean; }

const rowCls = (active: boolean) =>
  `flex h-[38px] items-center gap-[11px] rounded-lg px-3 text-[13px] transition-colors ${active ? "bg-[#333333] font-medium text-white" : "text-[#A6A6A6] hover:bg-[#262626] hover:text-white"}`;
const subCls = (active: boolean) =>
  `block rounded-lg py-[7px] pl-10 pr-3 text-[13px] transition-colors ${active ? "bg-[#333333] font-medium text-white" : "text-[#A6A6A6] hover:bg-[#262626] hover:text-white"}`;

interface SidebarContentProps {
  me: MeInfo | null;
  canAdmin: boolean;
  pathname: string;
  open: Record<string, boolean>;
  setOpen: (fn: (o: Record<string, boolean>) => Record<string, boolean>) => void;
  query: string;
  setQuery: (q: string) => void;
  results: NavItem[] | null;
  allItems: NavItem[];
  logout: () => void;
  onNavigate?: () => void;
  drawer?: boolean;
  searchRef?: { current: HTMLInputElement | null };
  onSearchEnter?: (href: string) => void;
}

/** The sidebar's inner content — rendered in the desktop flush panel and,
 *  identically, inside the mobile slide-in drawer (same design, same
 *  state). Mobile previously dumped all ~86 links as wrapping chips in a
 *  header, burying the page; the drawer is the proper pattern. */
function SidebarContent({ me, canAdmin, pathname, open, setOpen, query, setQuery, results, logout, onNavigate, searchRef, onSearchEnter, drawer }: SidebarContentProps) {
  const initials = (me?.name ?? "Rudra Singh").split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase();
  const go = () => { setQuery(""); onNavigate?.(); };
  return (
    <>
      <div className="px-4 pb-1 pt-4">
        <div className={`flex items-center gap-3 rounded-xl bg-[#262626] px-3 py-2.5 ${drawer ? "pr-11" : ""}`}>
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-white text-[#0F0F0F]">
            <ShieldIcon width="16" height="16" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13px] font-semibold leading-tight text-white">DSRclone</span>
            <span className="block text-[11px] leading-tight text-[#9C9C9C]">VAPT Console</span>
          </span>
          {drawer ? null : (<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#8A8A8A" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m8.5 9.5 3.5-3.5 3.5 3.5M8.5 14.5l3.5 3.5 3.5-3.5" /></svg>)}
        </div>

        <div className="relative mt-3">
          <SearchIcon className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#8A8A8A]" width="15" height="15" />
          <input ref={searchRef} value={query} onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && results?.[0]) { onSearchEnter?.(results[0].href); go(); } if (e.key === "Escape") setQuery(""); }}
            placeholder="Search" aria-label="Search navigation"
            className="h-[38px] w-full rounded-lg bg-[#262626] pl-9 pr-12 text-[13px] text-white placeholder-[#8A8A8A] outline-none ring-white/20 transition focus:ring-1" />
          <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded-md bg-[#3A3A3A] px-1.5 py-0.5 text-[10px] font-medium text-[#C9C9C9]">⌘K</kbd>
        </div>
      </div>

      <nav className="mt-2 flex-1 space-y-0.5 overflow-y-auto px-3 pb-3 [scrollbar-width:thin]">
        {results ? (
          results.length === 0 ? (
            <p className="px-3 py-2 text-[12.5px] text-[#8A8A8A]">No pages match your search.</p>
          ) : results.map((item) => (
            <Link key={item.href} href={item.href} onClick={go} className={rowCls(isActive(pathname, item.href))}>
              <span className="truncate">{item.label}</span>
            </Link>
          ))
        ) : (
          <>
            <Link href="/" onClick={go} className={rowCls(isActive(pathname, "/"))}>
              <GridIcon className="shrink-0" /><span>Overview</span>
            </Link>
            {GROUPS.map((group) => {
              const GroupIcon = group.icon;
              const expanded = Boolean(open[group.label]);
              const groupActive = group.items.some((i) => isActive(pathname, i.href));
              return (
                <div key={group.label}>
                  <button type="button" onClick={() => setOpen((o) => ({ ...o, [group.label]: !o[group.label] }))}
                    className={`${rowCls(groupActive)} w-full`}>
                    <GroupIcon className="shrink-0" />
                    <span className="flex-1 text-left">{group.label}</span>
                    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 text-[#8A8A8A] transition-transform duration-200 ${expanded ? "rotate-90" : ""}`}><path d="m9.5 5.5 6.5 6.5-6.5 6.5" /></svg>
                  </button>
                  {expanded ? (
                    <div className="space-y-0.5 py-0.5">
                      {group.items.map((item) => (
                        <Link key={item.href} href={item.href} onClick={go} className={subCls(isActive(pathname, item.href))}>{item.label}</Link>
                      ))}
                    </div>
                  ) : null}
                </div>
              );
            })}
            {canAdmin ? (
              <Link href="/admin" onClick={go} className={rowCls(pathname.startsWith("/admin"))}>
                <DiamondIcon className="shrink-0" /><span>Admin Panel</span>
              </Link>
            ) : null}
          </>
        )}
      </nav>

      <div className="border-t border-white/[0.06] p-3">
        <div className="flex items-center gap-3 rounded-lg px-2 py-1.5">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-[#333333] text-[12px] font-semibold text-white">{initials}</span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13px] font-medium leading-tight text-white">{me?.name ?? "…"}</span>
            <span className="block truncate text-[11.5px] leading-tight text-[#8A8A8A]">{me?.email ?? ""}</span>
          </span>
          <button type="button" onClick={logout} title="Sign out" aria-label="Sign out"
            className="shrink-0 rounded-lg p-2 text-[#8A8A8A] transition-colors hover:bg-[#262626] hover:text-white">
            <LogoutIcon width="16" height="16" />
          </button>
        </div>
      </div>
    </>
  );
}


export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { logout } = useAuth();
  const [me, setMe] = useState<MeInfo | null>(null);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [query, setQuery] = useState("");
  const [mobileOpen, setMobileOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (pathname === "/login" || !getToken()) return;
    let cancelled = false;
    apiFetch<MeInfo>("/auth/me").then((m) => { if (!cancelled) setMe(m); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [pathname]);

  useEffect(() => {
    const group = GROUPS.find((g) => g.items.some((i) => isActive(pathname, i.href)));
    if (group) setOpen((o) => ({ ...o, [group.label]: true }));
  }, [pathname]);

  useEffect(() => { setMobileOpen(false); }, [pathname]);
  useEffect(() => {
    document.body.style.overflow = mobileOpen ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [mobileOpen]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); searchRef.current?.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const allItems = useMemo(() => [{ href: "/", label: "Overview" }, ...GROUPS.flatMap((g) => g.items)], []);
  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return null;
    return allItems.filter((i) => i.label.toLowerCase().includes(q)).slice(0, 12);
  }, [query, allItems]);

  if (pathname === "/login") return <>{children}</>;
  const canAdmin = Boolean(me?.isPlatformAdmin) || me?.role === "OWNER" || me?.role === "ADMIN";
  const initials = (me?.name ?? "Rudra Singh").split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase();
  const contentProps = {
    me, canAdmin, pathname, open, setOpen, query, setQuery, results, allItems, logout,
    onSearchEnter: (href: string) => router.push(href),
  };

  return (
    <div className="flex min-h-screen bg-slate-950">
      <aside className="sticky top-0 hidden h-screen w-[264px] shrink-0 flex-col border-r border-white/[0.06] bg-[#0F0F0F] md:flex">
        <SidebarContent {...contentProps} searchRef={searchRef} />
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-40 flex items-center gap-3 border-b border-white/[0.06] bg-[#0F0F0F] px-4 py-3 md:hidden">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-white text-[#0F0F0F]">
            <ShieldIcon width="15" height="15" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13.5px] font-semibold leading-tight text-white">DSRclone</span>
            <span className="block truncate text-[11px] leading-tight text-[#8A8A8A]">{me?.name ?? "VAPT Console"}</span>
          </span>
          {canAdmin ? (
            <Link href="/admin" aria-label="Admin Panel" className="shrink-0 rounded-lg p-2 text-[#C9C9C9] transition-colors hover:bg-[#262626] hover:text-white">
              <DiamondIcon width="18" height="18" />
            </Link>
          ) : null}
          <button type="button" onClick={() => setMobileOpen(true)} aria-label="Open menu"
            className="shrink-0 rounded-lg p-2 text-white transition-colors hover:bg-[#262626]">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M4 7h16M4 12h16M4 17h16" /></svg>
          </button>
        </header>

        {mobileOpen ? (
          <div className="fixed inset-0 z-50 md:hidden" role="dialog" aria-modal="true" aria-label="Menu">
            <button type="button" aria-label="Close menu" onClick={() => setMobileOpen(false)} className="absolute inset-0 h-full w-full bg-black/60" />
            <div className="absolute left-0 top-0 flex h-full w-[280px] max-w-[85vw] flex-col bg-[#0F0F0F] shadow-2xl">
              <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close menu"
                className="absolute right-3 top-3 z-10 rounded-lg p-2 text-[#C9C9C9] transition-colors hover:bg-[#262626] hover:text-white">
                <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M6 6l12 12M18 6 6 18" /></svg>
              </button>
              <SidebarContent {...contentProps} drawer onNavigate={() => setMobileOpen(false)} />
            </div>
          </div>
        ) : null}

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
