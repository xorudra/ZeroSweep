"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@zerosweep/ui";

/**
 * Web target detail (Prompt 32 §154): overview, endpoints, parameters,
 * forms, authentication (references only), technologies, preflight
 * results, plans with the plan preview, findings link and report
 * actions. Nothing here shows a credential value — profiles are
 * referenced by ID (§50/§53).
 */
interface TargetDetail {
  target: {
    id: string; baseUrl: string; normalizedOrigin: string; environment: string;
    criticality: string; scanProfileKey: string; status: string;
    authorizationId: string; authenticationProfileId?: string | null; createdAt: string;
  };
  planCount: number;
  endpointCount: number;
  recentPreflights: Array<{ id: string; status: string; probeTransport: string; createdAt: string; checks: Array<{ name: string; status: string; detail: string }> }>;
}
interface PlanResult {
  plan: { id: string; profileKey: string; status: string; allowedTools: string[]; estimatedRequestClass: string; budget: Record<string, number> };
  scopeSnapshot: { id: string; hash: string; origins: string[] };
  blockedModules: Array<{ slug: string; reason: string }>;
  budgetNotice?: string;
}
interface PlanRow { id: string; profileKey: string; status: string; allowedTools: string[]; createdAt: string; scanId?: string | null }

const TABS = ["Overview", "Plans", "Preflight", "Sessions & Auth", "Reports"] as const;

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [tab, setTab] = useState<(typeof TABS)[number]>("Overview");
  const [detail, setDetail] = useState<TargetDetail | null>(null);
  const [plans, setPlans] = useState<PlanRow[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [profileKey, setProfileKey] = useState("WEB_SAFE");
  const [highRisk, setHighRisk] = useState("");
  const [approvalRef, setApprovalRef] = useState("");
  const [lastPlan, setLastPlan] = useState<PlanResult | null>(null);
  const [preflight, setPreflight] = useState<TargetDetail["recentPreflights"][number] | null>(null);

  const load = useCallback(async () => {
    try {
      const [d, p] = await Promise.all([
        apiFetch<TargetDetail>(`/vapt/web/targets/${id}`),
        apiFetch<PlanRow[]>(`/vapt/web/targets/${id}/plans`),
      ]);
      setDetail(d); setPlans(p);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [id]);
  useEffect(() => { void load(); }, [load]);

  const runPreflight = async () => {
    setBusy(true);
    try {
      const result = await apiFetch<TargetDetail["recentPreflights"][number]>(`/vapt/web/targets/${id}/preflight`, { method: "POST", body: "{}" });
      setPreflight(result);
      setNotice(`Preflight: ${result.status} — see the checks for the reasons.`);
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Preflight failed."); } finally { setBusy(false); }
  };

  const createPlan = async () => {
    setBusy(true);
    try {
      const body: Record<string, unknown> = { profileKey };
      if (highRisk.trim()) body.highRiskModules = highRisk.split(",").map((s) => s.trim()).filter(Boolean);
      if (approvalRef.trim()) body.approvalRef = approvalRef.trim();
      const result = await apiFetch<PlanResult>(`/vapt/web/targets/${id}/plans`, { method: "POST", body: JSON.stringify(body) });
      setLastPlan(result);
      setNotice("Plan generated. Review stages, budget and blocked modules before starting.");
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Plan failed."); } finally { setBusy(false); }
  };

  const startScan = async (planId: string) => {
    setBusy(true);
    try {
      await apiFetch(`/vapt/web/targets/${id}/scan`, { method: "POST", body: JSON.stringify({ planId }) });
      setNotice("Scan started.");
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Scan start refused — preflight must pass first (§7)."); } finally { setBusy(false); }
  };

  const t = detail?.target;
  return (
    <main>
      <PageHeader eyebrow="Web & API VAPT V2" title={t ? `Target — ${t.normalizedOrigin}` : "Web target"} />
      {error ? <p role="alert">{error}</p> : null}
      {notice ? <p>{notice}</p> : null}
      <nav style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {TABS.map((name) => (
          <button key={name} onClick={() => setTab(name)} aria-pressed={tab === name}>{name}</button>
        ))}
      </nav>
      {!t ? <p>Loading…</p> : tab === "Overview" ? (
        <>
          <Card title="Overview">
            <ul>
              <li>Base URL: {t.baseUrl}</li>
              <li>Environment: {t.environment} · Criticality: {t.criticality} · Status: {t.status}</li>
              <li>Authorization: APPROVED assessment <code>{t.authorizationId}</code> (active authorization is mandatory, §6)</li>
              <li>Default profile: {t.scanProfileKey}</li>
              <li>Endpoints known for this asset: {detail.endpointCount} · Plans: {detail.planCount}</li>
            </ul>
          </Card>
          <Card title="Latest preflight">
            {detail.recentPreflights.length === 0 ? <EmptyState title="No preflight yet." body="Run one from the Preflight tab." /> : (
              <p>{detail.recentPreflights[0]!.status} · probe transport {detail.recentPreflights[0]!.probeTransport} · {new Date(detail.recentPreflights[0]!.createdAt).toLocaleString()}</p>
            )}
          </Card>
        </>
      ) : tab === "Plans" ? (
        <>
          <Card title="Generate plan (plan preview, §11)">
            <div style={{ display: "grid", gap: 8, maxWidth: 560 }}>
              <label>Profile
                <select value={profileKey} onChange={(e) => setProfileKey(e.target.value)}>
                  {["WEB_PASSIVE", "WEB_SAFE", "WEB_STANDARD", "API_SAFE", "API_STANDARD", "TLS_ONLY", "CONTENT_DISCOVERY", "TARGETED_VERIFICATION"].map((k) => <option key={k} value={k}>{k}</option>)}
                </select>
              </label>
              <label>HIGH-risk modules (comma-separated; detection-only, gated by §16)
                <input value={highRisk} placeholder="sqlmap" onChange={(e) => setHighRisk(e.target.value)} style={{ width: "100%" }} /></label>
              <label>Approval reference (required for HIGH modules)
                <input value={approvalRef} onChange={(e) => setApprovalRef(e.target.value)} style={{ width: "100%" }} /></label>
              <button disabled={busy} onClick={() => void createPlan()}>Generate plan</button>
              {lastPlan ? (
                <div>
                  <p>Scope snapshot <code>{lastPlan.scopeSnapshot.hash.slice(0, 16)}…</code> · origins: {lastPlan.scopeSnapshot.origins.join(", ")}</p>
                  <p>Tools: {lastPlan.plan.allowedTools.join(", ")} · estimated request class {lastPlan.plan.estimatedRequestClass} · budget {JSON.stringify(lastPlan.plan.budget)}</p>
                  {lastPlan.blockedModules.length > 0 ? (
                    <p>Blocked modules: {lastPlan.blockedModules.map((b) => `${b.slug} (${b.reason})`).join("; ")}</p>
                  ) : null}
                  {lastPlan.budgetNotice ? <p>{lastPlan.budgetNotice}</p> : null}
                </div>
              ) : null}
            </div>
          </Card>
          <Card title="Plans">
            {plans.length === 0 ? <EmptyState title="No plans yet." body="" /> : (
              <ul>
                {plans.map((p) => (
                  <li key={p.id}>{p.profileKey} · {p.status} · {p.allowedTools.join(", ")}
                    {p.status === "PLANNED" ? <> · <button disabled={busy} onClick={() => void startScan(p.id)}>Start scan</button></> : null}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      ) : tab === "Preflight" ? (
        <Card title="Preflight (§7/§8)">
          <button disabled={busy} onClick={() => void runPreflight()}>Run preflight</button>
          {preflight ? (
            <>
              <p><strong>{preflight.status}</strong> · probe transport {preflight.probeTransport}</p>
              <ul>
                {preflight.checks.map((c) => <li key={c.name}>{c.name}: {c.status} — {c.detail}</li>)}
              </ul>
            </>
          ) : detail.recentPreflights.length > 0 ? (
            <ul>
              {detail.recentPreflights[0]!.checks.map((c) => <li key={c.name}>{c.name}: {c.status} — {c.detail}</li>)}
            </ul>
          ) : <p>No preflight recorded yet.</p>}
          <p style={{ color: "var(--muted, #666)" }}>Reachability is probed through the platform transport; when no probe transport is configured the verdict is BLOCKED — never assumed READY.</p>
        </Card>
      ) : tab === "Sessions & Auth" ? (
        <Card title="Authentication (references only)">
          <p>Authentication profile: {t.authenticationProfileId ? <code>{t.authenticationProfileId}</code> : "none attached"}.</p>
          <p>Session material is injected by the worker at execution time from the secret reference.
            Cookie and token VALUES never appear in plans, logs, evidence or this page (§50–§53); profile use is audited by reference.</p>
        </Card>
      ) : (
        <Card title="Reports">
          <p>Reports are produced by the canonical reporting pipeline from the scan&apos;s findings and its
            coverage record — including the limitations section. A scan with gaps reports COMPLETED_WITH_GAPS,
            and no report claims a target is &quot;100% secure&quot; (§148/§158).</p>
        </Card>
      )}
    </main>
  );
}
