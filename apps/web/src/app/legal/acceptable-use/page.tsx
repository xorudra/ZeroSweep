import { PageHeader } from "@/components/Shell";
import { Card } from "@zerosweep/ui";

/**
 * Acceptable Use Policy — the operating organization's published document for this
 * deployment, written from the product's actual behavior. Plain
 * language on purpose. Not legal advice.
 */
export default function Page() {
  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Legal" title="Acceptable Use Policy" body="The rules every account on this deployment operates under. Violations can end the account." />
      <Card>
        <div className="space-y-5 text-sm leading-relaxed text-slate-300">
          <section>
            <h3 className="mb-1 font-semibold text-white">Authorization is the whole point</h3>
            <p>Register and assess only targets you own, or targets whose owner has given you explicit written authorization to test. Never test a third party's system &quot;to see if it works&quot;, and never attempt to bypass the platform's ownership verification, scope limits, or approval workflow — they exist so that every scan is a lawful one.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Prohibited activity</h3>
            <p>Do not use the service to: perform denial-of-service or resource-exhaustion attacks; brute-force credentials; exploit systems beyond the platform's governed, policy-approved checks; distribute malware; probe or attack other users' organizations or data; create accounts to evade rate limits or bans; or break any applicable law.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Samples and evidence</h3>
            <p>Malicious samples may be handled only through the platform's designated analysis features and never distributed or deployed. Evidence you collect belongs in your reports — do not publish another party's sensitive data obtained through an assessment.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Enforcement</h3>
            <p>We may rate-limit, suspend, or terminate any account that violates this policy, and we may preserve related records for security or legal purposes. Termination does not transfer any responsibility for past activity: the legal responsibility for your testing is always yours.</p>
          </section>
          <p className="border-t border-slate-700 pt-4 text-xs text-slate-400">
            Last updated 10 October 2026 · Operator contact: forapikeyonly2008@gmail.com · These documents describe this hosted deployment and are not legal advice.
          </p>
        </div>
      </Card>
    </div>
  );
}
