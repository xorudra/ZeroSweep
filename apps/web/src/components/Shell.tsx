"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";
import { useAuth } from "@/lib/auth";

export const NAV = [
  { href: "/", label: "Overview" },
  { href: "/targets", label: "Targets" },
  { href: "/assets", label: "Assets" },
  { href: "/endpoints", label: "Endpoints" },
  { href: "/web-surface", label: "Web Surface" },
  { href: "/api-security", label: "API Security" },
  { href: "/network", label: "Network" },
  { href: "/code-security", label: "Code Security" },
  { href: "/containers", label: "Containers" },
  { href: "/kubernetes", label: "Kubernetes" },
  { href: "/compliance", label: "Compliance" },
  { href: "/grc", label: "GRC" },
  { href: "/grc/controls", label: "GRC Controls" },
  { href: "/grc/risks", label: "Risk Register" },
  { href: "/grc/audits", label: "Audits" },
  { href: "/grc/evidence", label: "Evidence" },
  { href: "/runtime-events", label: "Runtime Events" },
  { href: "/cloud-security", label: "Cloud Security" },
  { href: "/active-directory", label: "Active Directory" },
  { href: "/mobile-security", label: "Mobile Security" },
  { href: "/binary-security", label: "Binary Security" },
  { href: "/wireless-security", label: "Wireless Security" },
  { href: "/assessments", label: "Assessments" },
  { href: "/scans", label: "Scans" },
  { href: "/findings", label: "Findings" },
  { href: "/vulnerabilities", label: "Vulnerabilities" },
  { href: "/security-validation", label: "Security Validation" },
  { href: "/remediation", label: "Remediation" },
  { href: "/reports", label: "Reports" },
  { href: "/security-reports", label: "Security Reports" },
  { href: "/ai", label: "AI Copilot" },
  { href: "/ai/copilot", label: "Copilot Chat" },
  { href: "/continuous-security", label: "Continuous Security" },
  { href: "/automation/workflows", label: "Workflows" },
  { href: "/notifications", label: "Notifications" },
  { href: "/dashboard/executive", label: "Executive Dashboard" },
  { href: "/dashboard/security", label: "Security Dashboard" },
  { href: "/dashboard/remediation", label: "Remediation Dashboard" },
  { href: "/dashboard/assets", label: "Asset Risk" },
  { href: "/easm", label: "EASM" },
  { href: "/easm/assets", label: "External Assets" },
  { href: "/easm/unknown-assets", label: "Unknown Assets" },
  { href: "/easm/discovery", label: "EASM Discovery" },
  { href: "/easm/drift", label: "Exposure Drift" },
  { href: "/easm/technologies", label: "Technologies" },
  { href: "/easm/certificates", label: "Certificates" },
  { href: "/soc", label: "SOC" },
  { href: "/soc/alerts", label: "SOC Alerts" },
  { href: "/soc/incidents", label: "Incidents" },
  { href: "/soc/detections", label: "Detections" },
  { href: "/soc/threat-intelligence", label: "Threat Intel" },
  { href: "/analytics", label: "Analytics" },
  { href: "/analytics/attack-surface", label: "Attack Surface Intel" },
  { href: "/analytics/vulnerabilities", label: "Vuln Analytics" },
  { href: "/analytics/soc", label: "SOC Analytics" },
  { href: "/search", label: "Security Search" },
  { href: "/tools", label: "Tools" },
  { href: "/integrations", label: "Integrations" },
  { href: "/devsecops", label: "DevSecOps" },
  { href: "/remediation/tickets", label: "Remediation Tickets" },
  { href: "/audit-logs", label: "Audit Logs" },
  { href: "/settings", label: "Settings" },
] as const;

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const { logout } = useAuth();
  if (pathname === "/login") return <>{children}</>;
  return (
    <div className="flex min-h-screen bg-slate-950">
      <aside className="hidden w-60 shrink-0 border-r border-slate-800 bg-slate-900/40 md:block">
        <div className="p-5">
          <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400">Authorized VAPT Platform</p>
          <p className="mt-1 text-xl font-bold text-slate-50">DSRclone</p>
        </div>
        <nav className="space-y-1 px-3">
          {NAV.map((item) => {
            const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
            return (
              <Link key={item.href} href={item.href}
                className={`block rounded-lg px-3 py-2 text-sm ${active ? "bg-cyan-500/10 font-semibold text-cyan-300" : "text-slate-300 hover:bg-slate-800/60"}`}>
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="px-5 py-6">
          <button type="button" onClick={logout} className="text-sm text-slate-400 hover:text-slate-200">Sign out</button>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <header className="border-b border-slate-800 px-5 py-3 md:hidden">
          <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400">DSRclone</p>
          <nav className="mt-2 flex flex-wrap gap-2">
            {NAV.map((item) => (
              <Link key={item.href} href={item.href} className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-200">{item.label}</Link>
            ))}
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
