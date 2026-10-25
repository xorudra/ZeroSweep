"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@zerosweep/ui";

/**
 * Network target detail (Prompt 33 §8–§18): preflight, plan and scan
 * actions over one governed target. The plan view shows stages, tools,
 * the exact NSE scripts selected, every blocked item (Masscan gate,
 * FULL_TCP, brute/dos categories) and the frozen scope snapshot hash —
 * governance is visible before anything runs, and scan start honestly
 * refuses while the probe transport is NOT_CONFIGURED.
 */
interface TargetDetail {
  target: { id: string; targetType: string; targetValue: string; environment: string; criticality: string; scanProfileId: string; status: string };
  preflights: Array<{ id: string; status: string; probeTransport: string; checks: Array<{ name: string; status: string; detail: string }>; createdAt: string }>;
  plans: Array<{ id: string; profile: string; status: string; createdAt: string }>;
}
interface PlanResult {
  plan: { id: string; profile: string; status: string; stages: string[]; tools: string[]; scriptsUsed: Array<{ id: string; category: string }>; blockedItems: Array<{ item: string; reason: string }>; estimatedWorkloadClass: string; scanId?: string | null };
  scopeSnapshot: { id: string; hash: string; hosts: string[]; cidrs: string[] };
  budgetNotice?: string;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [detail, setDetail] = useState<TargetDetail | null>(null);
  const [planResult, setPlanResult] = useState<PlanResult | null>(null);
  const [profile, setProfile] = useState("NETWORK_SAFE");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setDetail(await apiFetch<TargetDetail>(`/vapt/network/targets/${id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true); setError(""); setNotice("");
    try { await fn(); setNotice(ok); await load(); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Action failed."); }
    finally { setBusy(false); }
  };

  const runPreflight = () => act(async () => {
    const row = await apiFetch<{ status: string }>(`/vapt/network/targets/${id}/preflight`, { method: "POST", body: "{}" });
    setNotice(`Preflight verdict: ${row.status} (transport NOT_CONFIGURED — reachability is never assumed).`);
  }, "Preflight recorded.");
  const runPlan = () => act(async () => {
    const res = await apiFetch<PlanResult>(`/vapt/network/targets/${id}/plans`, { method: "POST", body: JSON.stringify({ profileKey: profile }) });
    setPlanResult(res);
  }, "Plan created — scope snapshot frozen.");
  const runScan = () => act(async () => {
    await apiFetch(`/vapt/network/targets/${id}/scan`, { method: "POST", body: JSON.stringify(planResult ? { planId: planResult.plan.id } : {}) });
  }, "Scan started.");

  if (!detail) return <main><PageHeader eyebrow="Network VAPT V2" title="Network target" /><p>{error || "Loading…"}</p></main>;
  const t = detail.target;
  const latestPreflight = detail.preflights[0];
  return (
    <main>
      <PageHeader eyebrow="Network VAPT V2 · Target" title={t.targetValue} />
      <p style={{ color: "var(--muted, #666)" }}>
        {t.targetType} · {t.environment} · criticality {t.criticality} · default profile {t.scanProfileId} · {t.status}.
        Bound to an APPROVED assessment; the scope snapshot freezes at plan time and can never expand mid-scan (§11).
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {notice ? <p>{notice}</p> : null}

      <Card title="Preflight (§8/§9)">
        {latestPreflight ? (
          <>
            <p>Latest verdict: <strong>{latestPreflight.status}</strong> · transport {latestPreflight.probeTransport}</p>
            <ul>
              {latestPreflight.checks.map((c) => <li key={c.name}><strong>{c.name}</strong> — {c.status}: {c.detail}</li>)}
            </ul>
          </>
        ) : <EmptyState title="No preflight yet." body="Run preflight to evaluate authorization, scope size, rate policy and tool availability." />}
        <button disabled={busy} onClick={() => void runPreflight()}>Run preflight</button>
      </Card>

      <Card title="Scan plan (§10)">
        <label>Profile{" "}
          <select value={profile} onChange={(e) => setProfile(e.target.value)}>
            {["NETWORK_DISCOVERY", "NETWORK_SAFE", "NETWORK_STANDARD", "NETWORK_VULNERABILITY", "TLS_NETWORK", "TARGETED_SERVICE_VERIFICATION"].map((v) => <option key={v} value={v}>{v}</option>)}
          </select>
        </label>{" "}
        <button disabled={busy} onClick={() => void runPlan()}>Create plan</button>{" "}
        <button disabled={busy} onClick={() => void runScan()}>Start scan</button>
        {planResult ? (
          <div>
            <p>
              Plan {planResult.plan.id} · {planResult.plan.profile} · {planResult.plan.status} · workload {planResult.plan.estimatedWorkloadClass}
              {planResult.budgetNotice ? ` · ${planResult.budgetNotice}` : ""}
            </p>
            <p>Stages: {planResult.plan.stages.join(" → ")}</p>
            <p>Tools: {planResult.plan.tools.join(", ")}</p>
            <p>Scope snapshot: <code>{planResult.scopeSnapshot.hash}</code> · hosts [{planResult.scopeSnapshot.hosts.join(", ")}] · cidrs [{planResult.scopeSnapshot.cidrs.join(", ")}]</p>
            <p>NSE scripts selected (§38): {planResult.plan.scriptsUsed.map((s) => `${s.id} (${s.category})`).join(", ") || "—"}</p>
            {planResult.plan.blockedItems.length > 0 ? (
              <>
                <p><strong>Blocked items (governance, shown in the open):</strong></p>
                <ul>{planResult.plan.blockedItems.map((b) => <li key={b.item}><strong>{b.item}</strong> — {b.reason}</li>)}</ul>
              </>
            ) : <p>No blocked items.</p>}
          </div>
        ) : null}
        {detail.plans.length > 0 ? (
          <ul>
            {detail.plans.map((p) => <li key={p.id}>{p.profile} · {p.status} · {new Date(p.createdAt).toLocaleString()}</li>)}
          </ul>
        ) : null}
      </Card>

      <p><Link href="/vapt/network">← Back to Network VAPT</Link></p>
    </main>
  );
}
