"use client";

import Link from "next/link";
import { Card } from "@zerosweep/ui";
import { PageHeader } from "@/components/Shell";

export default function SettingsPage() {
  return (
    <>
      <PageHeader eyebrow="Settings" title="Organization & workspace settings"
        body="Roles: Owner (full control), Admin (manage users/settings), Security Engineer (targets, scope, approved assessments), Analyst (findings, reports, validation), Viewer (read-only). Backend RBAC is authoritative." />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card eyebrow="Credentials" title="Credential references">
          <p className="text-sm text-slate-400">
            ZeroSweep stores credential <strong className="text-slate-200">metadata and secret references only</strong> —
            never plaintext secrets. Manage them via the API under <code className="text-cyan-300">/api/v1/credentials</code> (Owner/Admin).
          </p>
        </Card>
        <Card eyebrow="Identity" title="Members, SSO & SCIM">
          <p className="text-sm text-slate-400">
            Enterprise identity (Prompt 23): organization members and invitations, OIDC/SAML single sign-on with
            break-glass recovery, SCIM provisioning with approved group → role mappings, access reviews, MFA and
            passkeys, device sessions, API keys and service accounts. Secrets are references only — never values.
          </p>
          <p className="mt-2 text-sm"><Link href="/settings/organization/members" className="text-sky-300 hover:underline">Members →</Link>{" · "}
          <Link href="/settings/organization/sso" className="text-sky-300 hover:underline">SSO & policy →</Link>{" · "}
          <Link href="/settings/organization/scim" className="text-sky-300 hover:underline">SCIM →</Link>{" · "}
          <Link href="/settings/organization/access-reviews" className="text-sky-300 hover:underline">Access reviews →</Link></p>
          <p className="mt-1 text-sm"><Link href="/settings/security/mfa" className="text-sky-300 hover:underline">My MFA & passkeys →</Link>{" · "}
          <Link href="/settings/security/sessions" className="text-sky-300 hover:underline">My sessions →</Link>{" · "}
          <Link href="/settings/api-keys" className="text-sky-300 hover:underline">API keys →</Link>{" · "}
          <Link href="/settings/service-accounts" className="text-sky-300 hover:underline">Service accounts →</Link></p>
        </Card>
        <Card eyebrow="Scanners" title="Scanner instances">
          <p className="text-sm text-slate-400">
            OWASP ZAP, Burp Suite Professional and Caido connect as admin-registered instances (Prompt 8).
            Register instances, run health checks, manage session profiles and active-scan approvals — by
            reference name only, never by URL or secret.
          </p>
          <p className="mt-2 text-sm"><Link href="/settings/scanners" className="text-sky-300 hover:underline">Open scanner instances →</Link></p>
        </Card>
        <Card eyebrow="AI Copilot" title="AI providers & policy">
          <p className="text-sm text-slate-400">
            Configure copilot providers (credential references only), models, data-classification policy,
            budgets and the golden evaluation suite (Prompt 21).
          </p>
          <p className="mt-2 text-sm"><Link href="/settings/ai" className="text-sky-300 hover:underline">Open AI settings →</Link></p>
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
