"use client";

import { useEffect, useState } from "react";
import { Badge, Card } from "@dsrclone/ui";
import { api } from "@/lib/api-client";

interface TemplatePolicy {
  snapshot: { collection: string; version: string; updatedAt: string };
  templates: { id: string; name: string; classification: string; vulnClass: string; severity: string; approvedForComprehensive?: boolean }[];
  selectionRules: {
    automated: string;
    neverAutomated: string[];
    approvedReviewByProfile: Record<string, string[]>;
    unknownTemplates: string;
    customTemplates: string;
  };
}

const CLASS_TONE: Record<string, string> = {
  SAFE: "LOW", REVIEW_REQUIRED: "MEDIUM", INTRUSIVE: "HIGH", DISABLED: "CRITICAL",
};

/**
 * Nuclei template-safety administration (Prompt 7 §47): shows the governed
 * template catalog exactly as the worker enforces it — classifications,
 * the frozen collection snapshot, and the selection rules. There is NO
 * upload control: arbitrary template paths can never enter a scan (§48).
 * The endpoint is OWNER/ADMIN-only; other roles simply see nothing here.
 */
export function TemplatePolicyPanel() {
  const [policy, setPolicy] = useState<TemplatePolicy | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.templatePolicy()
      .then((p) => { if (!cancelled) setPolicy(p as TemplatePolicy); })
      .catch(() => undefined); // 403 for non-admins — panel stays hidden
    return () => { cancelled = true; };
  }, []);

  if (!policy) return null;
  const counts = policy.templates.reduce<Record<string, number>>((acc, t) => {
    acc[t.classification] = (acc[t.classification] ?? 0) + 1;
    return acc;
  }, {});
  return (
    <div className="mt-4">
      <Card title="Nuclei template safety policy (admin)">
        <p className="text-sm text-slate-300">
          Governed collection <span className="text-slate-100">{policy.snapshot.collection}</span> · version{" "}
          <span className="text-slate-100">{policy.snapshot.version}</span> · updated {policy.snapshot.updatedAt}.
          Automated scans select {policy.selectionRules.automated.toLowerCase()}.{" "}
          {policy.selectionRules.neverAutomated.join(" and ")} templates are never selected automatically.
        </p>
        <p className="mt-2 text-xs text-slate-400">
          Counts: {Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(" · ")}.
          Unknown templates: {policy.selectionRules.unknownTemplates}
        </p>
        <div className="mt-3 overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full min-w-[520px] text-left text-sm">
            <thead className="bg-slate-900/70 text-slate-400">
              <tr><th className="px-4 py-2 font-medium">Template</th><th className="px-4 py-2 font-medium">Classification</th><th className="px-4 py-2 font-medium">Class</th><th className="px-4 py-2 font-medium">Notes</th></tr>
            </thead>
            <tbody>
              {policy.templates.map((t) => (
                <tr key={t.id} className="border-t border-slate-800">
                  <td className="px-4 py-2 text-slate-200">{t.id}<span className="block text-xs text-slate-500">{t.name}</span></td>
                  <td className="px-4 py-2"><Badge tone={CLASS_TONE[t.classification]}>{t.classification}</Badge></td>
                  <td className="px-4 py-2 text-slate-300">{t.vulnClass}</td>
                  <td className="px-4 py-2 text-slate-400">{t.approvedForComprehensive ? "Pre-approved for WEB_COMPREHENSIVE" : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-slate-500">
          Custom templates: {policy.selectionRules.customTemplates} There is deliberately no upload field on this page.
        </p>
      </Card>
    </div>
  );
}
