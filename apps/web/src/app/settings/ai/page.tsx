"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface ProviderRow { id: string; name: string; providerType: string; enabled: boolean; credentialConfigured: boolean; approvedClassifications: string[]; sourceCodeAllowance: string }
interface ModelRow { id: string; providerId: string; modelName: string; enabled: boolean; contextLimit: number; allowedTasks: string[] }
interface PolicyData { policy: { sourceCodeAccess: string; rawEvidenceAccess: string; enabledTasks: string[]; chatRetentionDays?: number }; budget: { dailyTokenLimit: number; monthlyTokenLimit: number; perTaskTokenLimit: number; maxRetrievalRecords: number } }

/**
 * AI administration (Prompt 21 §109). Providers hold credential
 * REFERENCES only — this page accepts a reference name and never a
 * secret value, and the API never returns one (§64/§110).
 */
export default function AiSettingsPage() {
  const [providers, setProviders] = useState<ProviderRow[]>([]);
  const [models, setModels] = useState<ModelRow[]>([]);
  const [policy, setPolicy] = useState<PolicyData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [form, setForm] = useState({ name: "", providerType: "MOCK", credentialRef: "", enabled: true });
  const [modelForm, setModelForm] = useState({ providerId: "", modelName: "" });

  const load = useCallback(async () => {
    try {
      const [p, m, pol] = await Promise.all([
        apiFetch<ProviderRow[]>("/ai/admin/providers"),
        apiFetch<ModelRow[]>("/ai/admin/models"),
        apiFetch<PolicyData>("/ai/admin/policy"),
      ]);
      setProviders(p); setModels(m); setPolicy(pol);
    } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const createProvider = async () => {
    setError(null);
    try {
      await apiFetch("/ai/admin/providers", { method: "POST", body: JSON.stringify(form) });
      setNotice("Provider saved. External transports report NOT_CONFIGURED until provisioned — health is never faked.");
      await load();
    } catch (e) { setError((e as Error).message); }
  };

  const createModel = async () => {
    setError(null);
    try {
      await apiFetch("/ai/admin/models", { method: "POST", body: JSON.stringify(modelForm) });
      await load();
    } catch (e) { setError((e as Error).message); }
  };

  const runEvaluation = async () => {
    setError(null);
    try {
      const run = await apiFetch<{ passed: number; failed: number }>("/ai/evaluations/run", { method: "POST", body: "{}" });
      setNotice(`Golden evaluation: ${run.passed} passed, ${run.failed} failed (groundedness, injection, secret-leak, tenant isolation).`);
    } catch (e) { setError((e as Error).message); }
  };

  const inputCls = "w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100";

  return (
    <>
      <PageHeader eyebrow="Settings" title="AI providers & policy"
        body="Configure copilot providers, models, data-classification policy, source-code/evidence access, budgets and retention. Admin (Owner/Admin) only — enforced by the API (§116)." />
      {error && <p className="mb-4 text-sm text-rose-300">{error}</p>}
      {notice && <p className="mb-4 text-sm text-emerald-300">{notice}</p>}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Providers (§64/§110)" eyebrow="Registry">
          {providers.length === 0
            ? <p className="text-sm text-slate-400">No providers. The copilot operates NOT_CONFIGURED with rule-based summaries.</p>
            : <ul className="space-y-2 text-sm">
                {providers.map((p) => (
                  <li key={p.id} className="flex items-center justify-between gap-2">
                    <span>{p.name} <span className="text-slate-500">({p.providerType})</span></span>
                    <span className="flex gap-1">
                      <Badge tone={p.enabled ? "success" : "neutral"}>{p.enabled ? "enabled" : "disabled"}</Badge>
                      <Badge tone="neutral">{p.credentialConfigured ? "credential ref set" : "no credential"}</Badge>
                    </span>
                  </li>
                ))}
              </ul>}
          <div className="mt-4 space-y-2">
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Provider name" className={inputCls} />
            <select value={form.providerType} onChange={(e) => setForm({ ...form, providerType: e.target.value })} className={inputCls}>
              <option value="MOCK">MOCK (deterministic, in-process)</option>
              <option value="OPENAI_COMPATIBLE">OpenAI-compatible (transport not provisioned)</option>
              <option value="ANTHROPIC">Anthropic (transport not provisioned)</option>
              <option value="LOCAL">LOCAL (organization-controlled)</option>
            </select>
            <input value={form.credentialRef} onChange={(e) => setForm({ ...form, credentialRef: e.target.value })}
              placeholder="Credential REFERENCE name only — never a secret value" className={inputCls} />
            <button onClick={() => void createProvider()} disabled={!form.name}
              className="rounded-lg bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">Add provider</button>
          </div>
        </Card>

        <Card title="Models (§4)" eyebrow="Registry">
          {models.length === 0
            ? <p className="text-sm text-slate-400">No models registered.</p>
            : <ul className="space-y-2 text-sm">
                {models.map((m) => (
                  <li key={m.id} className="flex items-center justify-between">
                    <span>{m.modelName} <span className="text-slate-500">ctx {m.contextLimit}</span></span>
                    <Badge tone={m.enabled ? "success" : "neutral"}>{m.enabled ? "enabled" : "disabled"}</Badge>
                  </li>
                ))}
              </ul>}
          <div className="mt-4 space-y-2">
            <select value={modelForm.providerId} onChange={(e) => setModelForm({ ...modelForm, providerId: e.target.value })} className={inputCls}>
              <option value="">Select provider…</option>
              {providers.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <input value={modelForm.modelName} onChange={(e) => setModelForm({ ...modelForm, modelName: e.target.value })} placeholder="Model name" className={inputCls} />
            <button onClick={() => void createModel()} disabled={!modelForm.providerId || !modelForm.modelName}
              className="rounded-lg bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">Add model</button>
          </div>
        </Card>

        <Card title="Data policy (§16/§17/§104)" eyebrow="Workspace policy">
          {!policy ? <p className="text-sm text-slate-400">Loading…</p> : (
            <ul className="space-y-1 text-sm text-slate-300">
              <li>Source-code access: <strong>{policy.policy.sourceCodeAccess}</strong> (default REDACTED)</li>
              <li>Raw-evidence access: <strong>{policy.policy.rawEvidenceAccess}</strong> (default SANITIZED_ONLY)</li>
              <li>Enabled tasks: {policy.policy.enabledTasks.length ? policy.policy.enabledTasks.join(", ") : "all"}</li>
              <li>Daily token budget: {policy.budget.dailyTokenLimit.toLocaleString()} · Monthly: {policy.budget.monthlyTokenLimit.toLocaleString()}</li>
              <li>Per-task token limit: {policy.budget.perTaskTokenLimit.toLocaleString()} · Max retrieval records: {policy.budget.maxRetrievalRecords}</li>
              <li>SECRET-classified data is never sent to external providers (§14) — enforced in code, not by prompt.</li>
            </ul>
          )}
        </Card>

        <Card title="Evaluation (§87)" eyebrow="Golden dataset">
          <p className="text-sm text-slate-400">
            Runs the controlled AI security suite against the live pipeline: groundedness and citation
            correctness over synthetic fixtures (SQLi, XSS, SSRF, CVE dependency, cloud, AD, mobile,
            binary, wireless), hallucination refusal, prompt-injection detection, secret-leak,
            cross-tenant and vector isolation.
          </p>
          <button onClick={() => void runEvaluation()}
            className="mt-3 rounded-lg bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20">Run golden evaluation</button>
        </Card>
      </div>
    </>
  );
}
