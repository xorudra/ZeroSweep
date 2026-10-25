import { PageHeader } from "@/components/Shell";
import { Card } from "@dsrclone/ui";

/**
 * Subprocessors — the operating organization's published document for this
 * deployment, written from the product's actual behavior. Plain
 * language on purpose. Not legal advice.
 */
export default function Page() {
  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Legal" title="Subprocessors" body="The providers this hosted deployment actually uses, and what each one touches." />
      <Card>
        <div className="space-y-5 text-sm leading-relaxed text-slate-300">
          <section>
            <h3 className="mb-1 font-semibold text-white">Render — application hosting</h3>
            <p>Runs the web console, API, AI service, and background worker (United States). Processes all service traffic in transit.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Neon — database</h3>
            <p>Managed PostgreSQL (United States) storing account, organization, target, and finding records.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Supabase — object storage</h3>
            <p>Private storage bucket (United States) for report artifacts and evidence files. Not publicly readable.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">UptimeRobot — availability monitoring</h3>
            <p>Pings the public health endpoints every few minutes. Receives only the service URLs and up/down status — no user data.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">AI provider route — copilot inference</h3>
            <p>Copilot requests are served through the operator's own AI gateway to free-tier model providers. Only redacted, normalized finding data is sent — never account credentials or raw evidence files.</p>
          </section>
          <section>
            <h3 className="mb-1 font-semibold text-white">Scope of this list</h3>
            <p>This list describes the hosted demo deployment. Anyone self-hosting ZeroSweep chooses their own providers, and this page places no obligations on them.</p>
          </section>
          <p className="border-t border-slate-700 pt-4 text-xs text-slate-400">
            Last updated 10 October 2026 · Operator contact: forapikeyonly2008@gmail.com · These documents describe this hosted deployment and are not legal advice.
          </p>
        </div>
      </Card>
    </div>
  );
}
