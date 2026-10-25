import { PageHeader } from "@/components/Shell";
import { Card } from "@zerosweep/ui";

/**
 * Privacy Policy — the operating organization's published document for this
 * deployment, written from the product's actual behavior. Plain
 * language on purpose. Not legal advice.
 */
export default function Page() {
  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Legal" title="Privacy Policy" body="What this deployment collects, why, and what it never does with your data." />
      <Card>
        <div className="space-y-5 text-sm leading-relaxed text-slate-300">
          <section>
            <h3 className="mb-1 font-semibold text-white">What we collect — account data</h3>
            <p>Your name, email address, and a bcrypt-hashed password (passwords are never stored or logged in plain text), plus your organizations, workspaces, and membership roles.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">What we collect — assessment data</h3>
            <p>The targets you register, ownership-verification details, scope definitions, scan configurations, findings, evidence artifacts, and reports you generate with the service.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">What we collect — security and operations data</h3>
            <p>Sign-in events and IP addresses (used for login protection and abuse prevention), an audit trail of significant actions inside your organization, and aggregated operational metrics such as request counts.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">How we use it</h3>
            <p>Only to operate and secure the service for you: running your assessments, enforcing the authorization policy, protecting accounts, preventing abuse, and supporting you. We do not sell personal data, and we do not use it for advertising.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">AI processing</h3>
            <p>When you use the copilot, normalized finding data is first passed through automated secret redaction — detected credentials and tokens are stripped — and only then sent to the configured AI provider to generate the answer. Account passwords and API keys are never sent. The providers used are listed on the Subprocessors page.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Tracking</h3>
            <p>This deployment runs no advertising trackers, no third-party analytics, and no session-replay tools. Your sign-in token is kept only in page memory while you use the console — it is never written to local storage — and your session is maintained with a secure, HttpOnly cookie that the server can revoke at any time.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Storage and security</h3>
            <p>Data is stored with the providers listed under Subprocessors, over encrypted connections. Report artifacts live in private object storage that is not publicly readable. Access inside the platform is controlled by accounts, roles, and tenant isolation between organizations.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Retention and your rights</h3>
            <p>Your data is kept while your account is active. You can review and correct your profile in Settings, and you may ask us at any time to export or delete your account and its data — contact us and we will action it. Deleting your account removes your organization's data except records we must keep for security or legal reasons.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Who this is for</h3>
            <p>ZeroSweep is a professional security tool and is not directed at children under 18.</p>
          </section>
          <p className="border-t border-slate-700 pt-4 text-xs text-slate-400">
            Last updated 10 October 2026 · Operator contact: forapikeyonly2008@gmail.com · These documents describe this hosted deployment and are not legal advice.
          </p>
        </div>
      </Card>
    </div>
  );
}
