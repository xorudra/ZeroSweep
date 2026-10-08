import { PageHeader } from "@/components/Shell";
import { Card } from "@dsrclone/ui";

/**
 * DRAFT PLACEHOLDER (Prompt 40 §166). This page reserves the route and
 * structure only. It is not legal advice and not a finalized policy —
 * the operating organization must have its own counsel-approved text
 * before any public launch.
 */
export default function Page() {
  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Legal — DRAFT PLACEHOLDER" title="Terms of Service" body="This is a structural placeholder, not a finalized legal document and not legal advice." />
      <Card>
        <div className="space-y-3 text-sm text-slate-300">
          <p><strong>Status: DRAFT — not in force.</strong> The final Terms of Service for any deployment of DSRclone is owned by the operating organization and must be reviewed by qualified legal counsel before customers rely on it.</p>
          <p>DSRclone is an authorized security-assessment platform. It is designed to test only systems the operator owns or is explicitly authorized to test; authorization attestation and scope enforcement are built into the product (see the Acceptable Use Policy and docs/product).</p>
          <p>No certification or compliance claim is made anywhere in this placeholder (§260): DSRclone does not claim PCI DSS, SOC 2, ISO 27001, GDPR or HIPAA certification.</p>
        </div>
      </Card>
    </div>
  );
}
