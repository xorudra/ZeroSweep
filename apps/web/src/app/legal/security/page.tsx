import { PageHeader } from "@/components/Shell";
import { Card } from "@dsrclone/ui";

/**
 * Security — the operating organization's published document for this
 * deployment, written from the product's actual behavior. Plain
 * language on purpose. Not legal advice.
 */
export default function Page() {
  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Legal" title="Security" body="How this deployment protects accounts and data — and how to report a problem." />
      <Card>
        <div className="space-y-5 text-sm leading-relaxed text-slate-300">
          <section>
            <h3 className="mb-1 font-semibold text-white">Account protection</h3>
            <p>Passwords are hashed with bcrypt and never stored in plain text. Sessions use short-lived signed tokens. Sign-in, password-reset, and MFA attempts are rate-limited per account and network address, and registration is rate-capped to prevent automated abuse. Multi-factor authentication (authenticator app) is available in Settings.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Platform controls</h3>
            <p>Every scan requires a verified target and an approved assessment — there is no way to run a scan against an unverified target through the product. Organizations are tenant-isolated: one organization cannot see another's targets, findings, or reports. Internal surfaces (metrics, administration, AI generation) are authenticated and rate-limited; the AI generation endpoint additionally requires a service key and enforces a hard request cap.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Honest limits</h3>
            <p>ZeroSweep does not claim PCI DSS, SOC 2, ISO 27001, GDPR, or HIPAA certification, and no page in this section should be read as such a claim.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Reporting a vulnerability</h3>
            <p>If you find a security problem in this deployment, contact forapikeyonly2008@gmail.com with the details. Please test only against your own account and data, give us a reasonable opportunity to fix the issue before disclosing it publicly, and we will acknowledge your report as quickly as we can.</p>
          </section>
          <p className="border-t border-slate-700 pt-4 text-xs text-slate-400">
            Last updated 10 October 2026 · Operator contact: forapikeyonly2008@gmail.com · These documents describe this hosted deployment and are not legal advice.
          </p>
        </div>
      </Card>
    </div>
  );
}
