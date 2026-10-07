"use client";

import Link from "next/link";
import { Card } from "@dsrclone/ui";
import { PageHeader } from "@/components/Shell";

export default function SettingsPage() {
  return (
    <>
      <PageHeader eyebrow="Settings" title="Organization & workspace settings"
        body="Roles: Owner (full control), Admin (manage users/settings), Security Engineer (targets, scope, approved assessments), Analyst (findings, reports, validation), Viewer (read-only). Backend RBAC is authoritative." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card eyebrow="Credentials" title="Credential references">
          <p className="text-sm text-slate-400">
            DSRclone stores credential <strong className="text-slate-200">metadata and secret references only</strong> —
            never plaintext secrets. Manage them via the API under <code className="text-cyan-300">/api/v1/credentials</code> (Owner/Admin).
          </p>
        </Card>
        <Card eyebrow="Scanners" title="Scanner instances">
          <p className="text-sm text-slate-400">
            OWASP ZAP, Burp Suite Professional and Caido connect as admin-registered instances (Prompt 8).
            Register instances, run health checks, manage session profiles and active-scan approvals — by
            reference name only, never by URL or secret.
          </p>
          <p className="mt-2 text-sm"><Link href="/settings/scanners" className="text-sky-300 hover:underline">Open scanner instances →</Link></p>
        </Card>
        <Card eyebrow="Schedules" title="Schedules">
          <p className="text-sm text-slate-400">Recurring assessments are configured here in a later phase. No schedule exists yet.</p>
        </Card>
        <Card eyebrow="Notifications" title="Notifications">
          <p className="text-sm text-slate-400">Scan completion, critical findings and approval requests will notify here and by email in a later phase.</p>
        </Card>
        <Card eyebrow="Safety" title="Safety defaults">
          <ul className="list-disc space-y-1 pl-5 text-sm text-slate-400">
            <li>Scans require a verified target and an approved assessment.</li>
            <li>Default scans are non-destructive; restricted capabilities are disabled by default.</li>
            <li>Internal/loopback/metadata targets are blocked unless an internal engagement is approved.</li>
            <li>Tools run only in isolated workers — never inside the web server.</li>
          </ul>
        </Card>
      </div>
    </>
  );
}
