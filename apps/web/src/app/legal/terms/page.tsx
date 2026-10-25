import { PageHeader } from "@/components/Shell";
import { Card } from "@dsrclone/ui";

/**
 * Terms of Service — the operating organization's published document for this
 * deployment, written from the product's actual behavior. Plain
 * language on purpose. Not legal advice.
 */
export default function Page() {
  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Legal" title="Terms of Service" body="The terms that govern use of this ZeroSweep deployment. By creating an account or using the service you agree to them." />
      <Card>
        <div className="space-y-5 text-sm leading-relaxed text-slate-300">
          <section>
            <h3 className="mb-1 font-semibold text-white">1. The service</h3>
            <p>ZeroSweep is an authorized vulnerability assessment and penetration-testing (VAPT) orchestration platform. It lets authorized users register targets, verify ownership, define scope, run governed security assessments, and generate reports. The service is provided by the deployment operator (&quot;we&quot;, &quot;us&quot;).</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">2. Authorized use only</h3>
            <p>You may assess only systems you own or that you have explicit, written authorization to test. The platform verifies target ownership and requires an approved assessment before any scan runs — those controls are a condition of use, not a formality. You alone are responsible for having valid authorization for every target you register, and for any consequences of testing without it.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">3. Your account</h3>
            <p>Provide accurate registration information, keep your credentials confidential, and do not share your account. You are responsible for all activity under your account. Tell us promptly if you believe your account has been compromised.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">4. Acceptable use</h3>
            <p>Use of the service is also governed by the Acceptable Use Policy, which forms part of these terms. We may suspend or terminate accounts that violate it, or that we reasonably believe are being used to test systems without authorization.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">5. Your data</h3>
            <p>Targets, scan configurations, findings, evidence and reports you create remain yours. You grant us only the rights needed to operate the service for you: to store, process, and display that data back to you and your organization.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">6. AI features</h3>
            <p>The AI copilot explains findings and drafts remediation guidance. Its answers are assistance, not professional advice, and may be wrong — verify before acting on them. The copilot performs analysis only; it never executes attacks or scans.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">7. Availability</h3>
            <p>This deployment is provided &quot;as is&quot; without warranties of any kind. We may change, suspend, or discontinue any part of the service, and we do not guarantee uptime or that the service will be error-free.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">8. Intellectual property</h3>
            <p>The platform and its branding belong to the operator and its licensors. Third-party and open-source components remain under their respective licenses. Nothing in these terms transfers any intellectual-property rights to you beyond your right to use the service.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">9. Liability</h3>
            <p>To the maximum extent permitted by law, we are not liable for indirect, incidental, or consequential damages arising from use of the service. Nothing in these terms limits liability that cannot be limited by law. You remain fully responsible for the legality of your own testing activity.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">10. Changes and termination</h3>
            <p>We may update these terms; the current version is always posted here, and continued use after a change means you accept it. You may stop using the service and delete your account at any time.</p>
          </section>
          <p className="border-t border-slate-700 pt-4 text-xs text-slate-400">
            Last updated 10 October 2026 · Operator contact: forapikeyonly2008@gmail.com · These documents describe this hosted deployment and are not legal advice.
          </p>
        </div>
      </Card>
    </div>
  );
}
