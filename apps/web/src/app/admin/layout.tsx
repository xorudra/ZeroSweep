"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

/**
 * Admin section shell — styled after the dark admin dashboard design the
 * product owner selected (deep-navy panels, hairline borders, magenta
 * accent). The main console keeps its own theme; the admin plane is a
 * visually distinct surface on purpose: you should always know when you
 * are operating the platform rather than using it.
 */
const TABS = [
  { href: "/admin", label: "Dashboard", exact: true },
  { href: "/admin/platform", label: "Platform Ops" },
  { href: "/admin/platform/queues", label: "Queues" },
  { href: "/admin/platform/workers", label: "Workers" },
  { href: "/admin/platform/backups", label: "Backups" },
  { href: "/admin/product", label: "Product & Plans" },
] as const;

export default function AdminLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  return (
    <div className="min-h-full bg-[#0A0F27] px-4 py-5 text-white md:px-7 md:py-7">
      <div className="mb-6 flex flex-wrap items-center gap-2">
        <span className="mr-3 inline-flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.18em] text-[#CB3CFF]">
          <span className="inline-block h-2 w-2 rounded-full bg-[#CB3CFF]" /> Admin
        </span>
        {TABS.map((tab) => {
          const active = "exact" in tab && tab.exact ? pathname === tab.href : pathname.startsWith(tab.href) && tab.href !== "/admin";
          const isActive = tab.href === "/admin" ? pathname === "/admin" : active;
          return (
            <Link key={tab.href} href={tab.href}
              className={`rounded-full px-3.5 py-1.5 text-[13px] ${isActive ? "bg-[#CB3CFF] font-semibold text-white" : "border border-[#232E57] bg-[#0D152F] text-[#AEB4D1] hover:text-white"}`}>
              {tab.label}
            </Link>
          );
        })}
      </div>
      {children}
    </div>
  );
}
