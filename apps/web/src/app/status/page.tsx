"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Public status page (Prompt 40 §163/§164): component health for Web
 * App, API, Scanning, Reports, AI and Integrations, sourced from the
 * deployment health endpoint. Incident communication follows
 * docs/product/incident-communication.md.
 */
interface Health { status: string; checks: Record<string, { status: string; detail?: string }> }

const COMPONENTS: Array<{ key: string; label: string; check: string }> = [
  { key: "web", label: "Web App", check: "web" },
  { key: "api", label: "API", check: "api" },
  { key: "scanning", label: "Scanning", check: "queue" },
  { key: "reports", label: "Reports", check: "database" },
  { key: "ai", label: "AI", check: "ai" },
  { key: "integrations", label: "Integrations", check: "redis" },
];

export default function Page() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setHealth(await apiFetch<Health>("/health"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Status unavailable.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="System" title="Status" body="Live component status for this ZeroSweep deployment. Values are measured from the health endpoint — a component that cannot be measured is shown as unknown, never as healthy." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {!health && !error && <EmptyState title="Loading status…" body="Checking components." />}
      {health && (
        <Card>
          <div className="mb-3 flex items-center gap-3">
            <h2 className="text-base font-semibold">Overall: {health.status}</h2>
            <Badge>{new Date().toLocaleString()}</Badge>
          </div>
          <ul className="divide-y divide-slate-800">
            {COMPONENTS.map((c) => {
              const check = health.checks[c.check];
              return (
                <li key={c.key} className="flex items-center justify-between py-2 text-sm">
                  <span>{c.label}</span>
                  <span className="text-slate-400">{check ? `${check.status}${check.detail ? ` — ${check.detail}` : ""}` : "unknown (not measured)"}</span>
                </li>
              );
            })}
          </ul>
        </Card>
      )}
    </div>
  );
}
