"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type ReactNode, type SVGProps } from "react";
import { useAuth } from "@/lib/auth";
import { apiFetch } from "@/lib/api-client";

/**
 * Console shell — "True-black flat" system (taste-skill app sheet,
 * 2026-10-23; structure kept from the owner-selected sidebar design
 * #3, Raafi G, CC BY 4.0): sidebar and page share one true-black
 * ground divided by a single 1px rule (#1A1A1A); the workspace
 * switcher sits flat at the top, a search field with a ⌘K badge
 * live-filters the navigation, and the user profile is pinned at the
 * bottom. The active nav item is marked by brightness alone — its
 * label goes from #B4B4B4 to white, no filled pill, no accent colour
 * on chrome anywhere. The five steps of the normal road (PRIMARY
 * below) sit flat at the top; our 86 destinations sit behind the
 * eight "Advanced tools" group rows, which expand in place and the
 * group holding the current page opens automatically.
 */

type IconProps = SVGProps<SVGSVGElement>;
const ic = (path: ReactNode) => function Icon(props: IconProps) {
  return (
    <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...props}>{path}</svg>
  );
};
const GridIcon = ic(<><rect x="3.5" y="3.5" width="7" height="7" rx="1.8" /><rect x="13.5" y="3.5" width="7" height="7" rx="1.8" /><rect x="3.5" y="13.5" width="7" height="7" rx="1.8" /><rect x="13.5" y="13.5" width="7" height="7" rx="1.8" /></>);
const ClipboardIcon = ic(<><rect x="5" y="4.5" width="14" height="17" rx="2" /><path d="M9 4.5a3 3 0 0 1 6 0" /><path d="M9 12h6M9 16h4" /></>);
const DocIcon = ic(<><path d="M6 3.5h8L19 8v12.5H6Z" /><path d="M13.5 3.5V8H19M9 13h6M9 16.5h4" /></>);
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

/**
 * The normal road, always visible at the top of the sidebar: the five
 * pages a user actually needs, in the order the work flows. Everything
 * else lives below under "Advanced tools" (the GROUPS index above) —
 * nothing is removed, it just stops shouting over the main flow.
 * Owner order 2026-10-20: "make it simple and guided".
 */
const PRIMARY: { href: string; label: string; hint: string; icon: (props: IconProps) => JSX.Element }[] = [
  { href: "/targets", label: "1 · Add a target", hint: "Add it, then verify it's yours", icon: RadarIcon },
  { href: "/assessments", label: "2 · Plan & approve", hint: "The check, agreed first", icon: ClipboardIcon },
  { href: "/scans", label: "3 · Run the scan", hint: "Watch it work", icon: PulseIcon },
  { href: "/findings", label: "4 · Read findings", hint: "Problems, worst first", icon: BugIcon },
  { href: "/reports", label: "5 · Get the report", hint: "Download & share", icon: DocIcon },
];

const isActive = (pathname: string, href: string) =>
  href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`);

interface MeInfo { name?: string; email?: string; role?: string; isPlatformAdmin?: boolean; }

const rowCls = (active: boolean) =>
  `flex h-[38px] items-center gap-[11px] rounded-lg px-3 text-[13px] transition-colors ${active ? "font-medium text-white" : "text-[#B4B4B4] hover:bg-[#111111] hover:text-white"}`;
const subCls = (active: boolean) =>
  `block rounded-lg py-[7px] pl-10 pr-3 text-[13px] transition-colors ${active ? "font-medium text-white" : "text-[#B4B4B4] hover:bg-[#111111] hover:text-white"}`;

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
        <div className={`flex items-center gap-3 px-3 py-2 ${drawer ? "pr-11" : ""}`}>
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-white text-[#0F0F0F]">
            <ShieldIcon width="16" height="16" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13px] font-semibold leading-tight text-white">DSRclone</span>
            <span className="block text-[11px] leading-tight text-[#949494]">VAPT Console</span>
          </span>
          {drawer ? null : (<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#949494" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><path d="m8.5 9.5 3.5-3.5 3.5 3.5M8.5 14.5l3.5 3.5 3.5-3.5" /></svg>)}
        </div>

        <div className="relative mt-3">
          <SearchIcon className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-[#949494]" width="15" height="15" />
          <input ref={searchRef} value={query} onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter" && results?.[0]) { onSearchEnter?.(results[0].href); go(); } if (e.key === "Escape") setQuery(""); }}
            placeholder="Search" aria-label="Search navigation"
            className="h-9 w-full rounded-full border border-[#2E2E2E] bg-[#111111] pl-9 pr-12 text-[13px] text-white placeholder-[#949494] outline-none transition focus:border-[#444444]" />
          <kbd className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded-md bg-[#2A2A2A] px-1.5 py-0.5 text-[10px] font-medium text-[#B4B4B4]">⌘K</kbd>
        </div>
      </div>

      <nav className="mt-2 flex-1 space-y-0.5 overflow-y-auto px-3 pb-3 [scrollbar-width:thin]">
        {results ? (
          results.length === 0 ? (
            <p className="px-3 py-2 text-[12.5px] text-[#949494]">No pages match your search.</p>
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
            <p className="px-3 pb-1 pt-4 text-xs text-[#949494]">Start here — the normal road</p>
            {PRIMARY.map((item) => {
              const ItemIcon = item.icon;
              return (
                <Link key={item.href} href={item.href} onClick={go} className={rowCls(isActive(pathname, item.href))}>
                  <ItemIcon className="shrink-0" />
                  <span className="min-w-0">
                    <span className="block truncate leading-tight">{item.label}</span>
                    <span className="block truncate text-[11px] leading-tight text-[#949494]">{item.hint}</span>
                  </span>
                </Link>
              );
            })}
            <p className="px-3 pb-1 pt-4 text-xs text-[#949494]">Advanced tools</p>
            {GROUPS.map((group) => {
              const GroupIcon = group.icon;
              const expanded = Boolean(open[group.label]);
              const groupActive = group.items.some((i) => isActive(pathname, i.href));
              return (
                <div key={group.label}>
                  <button type="button" aria-expanded={expanded} onClick={() => setOpen((o) => ({ ...o, [group.label]: !o[group.label] }))}
                    className={`${rowCls(groupActive)} w-full`}>
                    <GroupIcon className="shrink-0" />
                    <span className="flex-1 text-left">{group.label}</span>
                    <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className={`shrink-0 text-[#949494] transition-transform duration-200 ${expanded ? "rotate-90" : ""}`}><path d="m9.5 5.5 6.5 6.5-6.5 6.5" /></svg>
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

      <div className="border-t border-[#1A1A1A] p-3">
        <div className="flex items-center gap-1 rounded-lg px-2 py-1.5">
          <Link href="/profile" onClick={go} className="flex min-w-0 flex-1 items-center gap-3 rounded-lg" title="Your profile">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-[#2A2A2A] text-[12px] font-semibold text-white">{initials}</span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[13px] font-medium leading-tight text-white">{me?.name ?? "…"}</span>
              <span className="block truncate text-[11.5px] leading-tight text-[#949494]">{me?.email ?? ""}</span>
            </span>
          </Link>
          <button type="button" onClick={logout} title="Sign out" aria-label="Sign out"
            className="shrink-0 rounded-lg p-2 text-[#949494] transition-colors hover:bg-[#111111] hover:text-white">
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
  const { logout, authenticated } = useAuth();
  const [me, setMe] = useState<MeInfo | null>(null);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [query, setQuery] = useState("");
  const [mobileOpen, setMobileOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (pathname === "/login" || !authenticated) return;
    let cancelled = false;
    (async () => {
      // Retry a couple of times: while the API is waking up, a failed
      // /auth/me used to leave the shell without the account (and its
      // Admin Panel link) until the next navigation or a re-login.
      for (const delay of [0, 1500, 3500]) {
        if (delay) await new Promise((r) => setTimeout(r, delay));
        if (cancelled) return;
        try {
          const m = await apiFetch<MeInfo>("/auth/me");
          if (!cancelled) setMe(m);
          return;
        } catch { /* wake-up in progress — retry */ }
      }
    })();
    return () => { cancelled = true; };
  }, [pathname, authenticated]);

  useEffect(() => {
    const group = GROUPS.find((g) => g.items.some((i) => isActive(pathname, i.href)));
    if (group) setOpen((o) => ({ ...o, [group.label]: true }));
  }, [pathname]);

  useEffect(() => { setMobileOpen(false); }, [pathname]);
  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setMobileOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mobileOpen]);
  useEffect(() => {
    document.body.style.overflow = mobileOpen ? "hidden" : "";
    return () => { document.body.style.overflow = ""; };
  }, [mobileOpen]);

  useEffect(() => {
    // One front door: opening the console wakes the rest of the
    // deployment. On the free tier the AI and worker services sleep when
    // idle; these fire-and-forget pings start them booting in the
    // background (the API is woken by the /auth/me call above). The
    // replies don't matter — the requests themselves do the waking.
    const ai = process.env.NEXT_PUBLIC_AI_URL ?? "https://dsrclone-ai.onrender.com";
    const worker = process.env.NEXT_PUBLIC_WORKER_URL ?? "https://dsrclone-worker.onrender.com";
    for (const url of [`${ai}/health`, worker]) {
      fetch(url, { mode: "no-cors", cache: "no-store" }).catch(() => undefined);
    }
  }, []);

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

  if (pathname === "/login" || pathname === "/invite") return <>{children}</>;
  if (pathname === "/legal" || pathname.startsWith("/legal/")) {
    // Public documents: no console chrome (the sidebar belongs to the
    // signed-in console, and a signed-out reader has no session behind
    // it). A slim header with a path back to sign-in is all they need.
    return (
      <div className="min-h-screen bg-black">
        <header className="border-b border-[#1A1A1A] bg-black px-5 py-3">
          <div className="mx-auto flex max-w-5xl items-center gap-3">
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-white text-[#0F0F0F]">
              <ShieldIcon width="15" height="15" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[13.5px] font-semibold leading-tight text-white">DSRclone</span>
              <span className="block text-[11px] leading-tight text-[#949494]">Legal documents</span>
            </span>
            <Link href="/login" className="shrink-0 rounded-full bg-white px-3.5 py-2 text-[13px] font-medium text-black transition-colors hover:bg-[#E6E6E6]">Sign in</Link>
          </div>
          <nav aria-label="Legal documents" className="mx-auto mt-3 flex max-w-5xl flex-wrap gap-1.5">
            {[
              { href: "/legal/terms", label: "Terms of Service" },
              { href: "/legal/privacy", label: "Privacy Policy" },
              { href: "/legal/acceptable-use", label: "Acceptable Use" },
              { href: "/legal/security", label: "Security" },
              { href: "/legal/subprocessors", label: "Subprocessors" },
            ].map((d) => (
              <Link key={d.href} href={d.href}
                className={`rounded-lg px-2.5 py-1.5 text-[12.5px] transition-colors ${pathname === d.href ? "font-medium text-white" : "text-[#B4B4B4] hover:bg-[#111111] hover:text-white"}`}>
                {d.label}
              </Link>
            ))}
          </nav>
        </header>
        <main className="mx-auto max-w-5xl p-5 md:p-8">{children}</main>
      </div>
    );
  }
  const canAdmin = Boolean(me?.isPlatformAdmin) || me?.role === "OWNER" || me?.role === "ADMIN";
  const initials = (me?.name ?? "Rudra Singh").split(" ").map((p) => p[0]).slice(0, 2).join("").toUpperCase();
  const contentProps = {
    me, canAdmin, pathname, open, setOpen, query, setQuery, results, allItems, logout,
    onSearchEnter: (href: string) => router.push(href),
  };

  return (
    <div className="flex min-h-screen bg-black">
      <aside className="sticky top-0 hidden h-screen w-[264px] shrink-0 flex-col border-r border-[#1A1A1A] bg-black md:flex">
        <SidebarContent {...contentProps} searchRef={searchRef} />
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-40 flex items-center gap-3 border-b border-[#1A1A1A] bg-black px-4 py-3 md:hidden">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-white text-[#0F0F0F]">
            <ShieldIcon width="15" height="15" />
          </span>
          <span className="min-w-0 flex-1">
            <span className="block truncate text-[13.5px] font-semibold leading-tight text-white">DSRclone</span>
            <span className="block truncate text-[11px] leading-tight text-[#949494]">{me?.name ?? "VAPT Console"}</span>
          </span>
          {canAdmin ? (
            <Link href="/admin" aria-label="Admin Panel" className="shrink-0 rounded-lg p-2 text-[#B4B4B4] transition-colors hover:bg-[#111111] hover:text-white">
              <DiamondIcon width="18" height="18" />
            </Link>
          ) : null}
          <button type="button" onClick={() => setMobileOpen(true)} aria-label="Open menu"
            className="shrink-0 rounded-lg p-2 text-white transition-colors hover:bg-[#111111]">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" aria-hidden><path d="M4 7h16M4 12h16M4 17h16" /></svg>
          </button>
        </header>

        {mobileOpen ? (
          <div className="fixed inset-0 z-50 md:hidden" role="dialog" aria-modal="true" aria-label="Menu">
            <button type="button" aria-label="Close menu" onClick={() => setMobileOpen(false)} className="absolute inset-0 h-full w-full bg-black/60" />
            <div className="absolute left-0 top-0 flex h-full w-[280px] max-w-[85vw] flex-col bg-black shadow-2xl">
              <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close menu"
                className="absolute right-3 top-3 z-10 rounded-lg p-2 text-[#B4B4B4] transition-colors hover:bg-[#111111] hover:text-white">
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

/**
 * Page header — one noun title at 20px/600 and one plain sentence
 * under it. The old mono uppercase cyan kicker (`eyebrow`) is gone
 * everywhere (taste house rule: no eyebrows); the prop is still
 * accepted so all existing call sites keep working.
 */
export function PageHeader({ title, body }: { eyebrow?: string; title: string; body?: string }) {
  return (
    <div className="mb-6">
      <h1 className="text-xl font-semibold text-white">{title}</h1>
      {body ? <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-slate-300">{body}</p> : null}
    </div>
  );
}
