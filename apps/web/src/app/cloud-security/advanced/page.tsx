"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * Cloud Security V2 (Prompt 34 §1/§126). Connection tests, the Cloud
 * Posture Orchestrator (§103), versioned baselines + drift (§97/§100),
 * coverage with explicit gaps (§110/§111), Steampipe approved packs
 * (§24), attack-path candidates (§32) and the deterministic NL query
 * box (§137). Cloud access is READ-ONLY (§5): no control here can
 * change a cloud resource, and a missing permission is reported as a
 * gap — never as "clean".
 */
interface AccountRow { id: string; provider: string; name: string; externalAccountId: string; environment: string; credentialConfigured: boolean }
interface ConnTest { id: string; result: string; detail: string; testedAt: string; tenantVerified: boolean; authorizedRegions: number }
interface RunRow { id: string; status: string; pipeline: Array<{ stage: string; status: string; detail: string }>; createdAt: string }
interface PathRow { id: string; findingId?: string | null; steps: Array<{ label: string; evidence: string }>; confidence: string; theoretical: boolean }
interface CoverageRow { id: string; completion: string; accountsCovered: number; resourcesObserved: number; gaps: Array<{ area: string; reason: string; detail: string }> }
interface BaselineRow { id: string; version: number; hash: string; createdAt: string }
interface Deviation { ruleId: string; observed: string; message: string }
interface ReportDef { reportType: string; title: string; noCertificationStatement: string }
interface Pack { id: string; title: string; provider: string; queries: Array<{ id: string; title: string }> }

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const btnCls = "rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50";

export default function Page() {
  const [accounts, setAccounts] = useState<AccountRow[]>([]);
  const [selected, setSelected] = useState("");
  const [tests, setTests] = useState<ConnTest[]>([]);
  const [runs, setRuns] = useState<RunRow[]>([]);
  const [paths, setPaths] = useState<PathRow[]>([]);
  const [coverage, setCoverage] = useState<CoverageRow[]>([]);
  const [baselines, setBaselines] = useState<BaselineRow[]>([]);
  const [deviations, setDeviations] = useState<Deviation[]>([]);
  const [reports, setReports] = useState<ReportDef[]>([]);
  const [packs, setPacks] = useState<Pack[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [nlText, setNlText] = useState("");
  const [nlResult, setNlResult] = useState("");

  const load = useCallback(async () => {
    try {
      const [acc, pth, cov, base, rep, pk] = await Promise.all([
        apiFetch<{ items: AccountRow[] }>("/cloud/accounts"),
        apiFetch<{ items: PathRow[] }>("/cloud/attack-paths"),
        apiFetch<{ items: CoverageRow[] }>("/cloud/coverage"),
        apiFetch<{ items: BaselineRow[] }>("/cloud/baselines"),
        apiFetch<{ items: ReportDef[] }>("/cloud/reports"),
        apiFetch<{ items: Pack[] }>("/cloud/steampipe-packs"),
      ]);
      setAccounts(acc.items ?? []);
      setPaths(pth.items ?? []);
      setCoverage(cov.items ?? []);
      setBaselines(base.items ?? []);
      setReports(rep.items ?? []);
      setPacks(pk.items ?? []);
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load cloud security V2");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<string>) => {
    setBusy(key);
    setNotice("");
    try { setNotice(await fn()); } catch (err) { setNotice(err instanceof ApiError ? err.message : "Action failed"); }
    setBusy(null);
  };

  const testConnection = (id: string) => act(`test-${id}`, async () => {
    const out = await apiFetch<{ evaluation: { result: string; detail: string } }>(`/cloud/accounts/${id}/test`, { method: "POST" });
    const hist = await apiFetch<{ items: ConnTest[] }>(`/cloud/accounts/${id}/connection-tests`);
    setTests(hist.items ?? []);
    setSelected(id);
    return `Connection test: ${out.evaluation.result} — ${out.evaluation.detail}`;
  });

  const assess = (id: string) => act(`assess-${id}`, async () => {
    const out = await apiFetch<{ run: RunRow }>(`/cloud/accounts/${id}/assess`, { method: "POST", body: "{}" });
    const [r, cov, pth] = await Promise.all([
      apiFetch<{ items: RunRow[] }>("/cloud/runs"),
      apiFetch<{ items: CoverageRow[] }>("/cloud/coverage"),
      apiFetch<{ items: PathRow[] }>("/cloud/attack-paths"),
    ]);
    setRuns(r.items ?? []);
    setCoverage(cov.items ?? []);
    setPaths(pth.items ?? []);
    return `Assessment ${out.run.id}: ${out.run.status}`;
  });

  const createBaseline = () => act("baseline", async () => {
    const b = await apiFetch<BaselineRow>("/cloud/baselines", { method: "POST", body: JSON.stringify({ cloudAccountId: selected || accounts[0]?.id }) });
    const base = await apiFetch<{ items: BaselineRow[] }>("/cloud/baselines");
    setBaselines(base.items ?? []);
    return `Baseline v${b.version} created (hash ${b.hash.slice(0, 12)}…)`;
  });

  const checkDrift = () => act("drift", async () => {
    const out = await apiFetch<{ deviations: Deviation[] }>(`/cloud/baseline-drift?accountId=${encodeURIComponent(selected || accounts[0]?.id || "")}`);
    setDeviations(out.deviations ?? []);
    return `${(out.deviations ?? []).length} baseline deviation(s)`;
  });

  const runNl = () => act("nl", async () => {
    const out = await apiFetch<{ refused: boolean; reason?: string; rows?: Array<{ name?: string; id: string }>; executed: boolean }>("/cloud/nl-query", { method: "POST", body: JSON.stringify({ text: nlText }) });
    if (out.refused) { setNlResult(`Refused: ${out.reason}`); return "The copilot refused this request (§136)"; }
    setNlResult(`${(out.rows ?? []).length} record(s): ${(out.rows ?? []).map((r) => r.name ?? r.id).join(", ") || "none"}`);
    return "Query answered from stored records — nothing was executed (§137)";
  });

  if (state === "loading") return <div className="p-6 text-slate-400">Loading cloud security V2…</div>;
  if (state === "error") return <div className="p-6 text-red-400">{error}</div>;

  const latestCoverage = coverage[0];

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Prompt 34" title="Cloud Security — Advanced (V2)" body="Connection tests, posture orchestration, baselines, coverage & attack paths. Read-only: the platform never changes a cloud resource (Prompt 34 §5/§126)." />
      <p className="text-sm text-slate-400"><Link href="/cloud-security" className="underline">← Cloud security dashboard</Link></p>
      {notice ? <div className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-200">{notice}</div> : null}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Accounts" value={accounts.length} />
        <StatCard label="Attack-path candidates" value={paths.length} />
        <StatCard label="Baselines" value={baselines.length} />
        <StatCard label="Latest completion" value={latestCoverage?.completion ?? "—"} />
      </div>

      <Card title="Accounts — connection test & posture assessment (§12/§103)">
        {accounts.length === 0 ? <EmptyState title="No cloud accounts" body="Register an account on the cloud security dashboard first." /> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Account</th><th>Provider</th><th>Environment</th><th>Credential</th><th>Actions</th></tr></thead>
            <tbody>
              {accounts.map((a) => (
                <tr key={a.id} className="border-t border-slate-800">
                  <td className="py-2">{a.name}<div className="text-xs text-slate-500">{a.externalAccountId}</div></td>
                  <td>{a.provider}</td>
                  <td><Badge>{a.environment}</Badge></td>
                  <td>{a.credentialConfigured ? "reference configured" : "no reference"}</td>
                  <td className="space-x-2">
                    <button className={btnCls} disabled={busy !== null} onClick={() => void testConnection(a.id)}>Test connection</button>
                    <button className={btnCls} disabled={busy !== null} onClick={() => void assess(a.id)}>Assess</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {tests.length ? (
          <div className="mt-3 text-xs text-slate-400">
            <p className="font-medium text-slate-300">Connection history{selected ? ` — ${selected}` : ""}</p>
            {tests.map((t) => <p key={t.id}>{t.testedAt} — <Badge>{t.result}</Badge> tenant verified: {String(t.tenantVerified)}, regions: {t.authorizedRegions}. {t.detail}</p>)}
          </div>
        ) : null}
      </Card>

      <Card title="Assessment runs (§103 pipeline)">
        {runs.length === 0 ? <EmptyState title="No V2 runs yet" body="Run an assessment above; the pipeline is validate → connect → inventory → posture → IAM → exposure → vulnerability → compliance → correlation → risk → remediation → report." /> : (
          <div className="space-y-2 text-sm">
            {runs.slice(0, 3).map((r) => (
              <div key={r.id} className="rounded bg-slate-900 p-2">
                <p>{r.id} — <Badge>{r.status}</Badge> <span className="text-xs text-slate-500">{r.createdAt}</span></p>
                <p className="text-xs text-slate-400">{(r.pipeline ?? []).map((s) => `${s.stage}: ${s.status}`).join(" · ")}</p>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Coverage & gaps (§110/§111) — a gap is never shown as 'clean'">
        {latestCoverage ? (
          <div className="text-sm">
            <p>Accounts covered: {latestCoverage.accountsCovered} · Resources observed: {latestCoverage.resourcesObserved} · Completion: <Badge>{latestCoverage.completion}</Badge></p>
            <ul className="mt-2 list-disc pl-5 text-slate-300">
              {latestCoverage.gaps.map((g, i) => <li key={i}><span className="text-slate-100">{g.area}</span> — {g.reason}: {g.detail}</li>)}
            </ul>
          </div>
        ) : <EmptyState title="No coverage recorded" body="Coverage is computed by each assessment run." />}
      </Card>

      <Card title="Attack-path candidates (§32) — Observed Evidence · Inferred Relationship · Potential Path">
        {paths.length === 0 ? <EmptyState title="No candidates" body="Candidates are derived analytically from exposure + IAM graph data. They are never executed (§33)." /> : (
          <div className="space-y-2 text-sm">
            {paths.map((p) => (
              <div key={p.id} className="rounded bg-slate-900 p-2">
                <p>Confidence <Badge>{p.confidence}</Badge> {p.theoretical ? <Badge>theoretical</Badge> : null}</p>
                <ol className="mt-1 list-decimal pl-5 text-slate-300">
                  {p.steps.map((s, i) => <li key={i}>{s.label} <span className="text-xs text-slate-500">[{s.evidence}]</span></li>)}
                </ol>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Cloud Security Baseline (§97) & drift (§100)">
        <div className="flex flex-wrap gap-2">
          <button className={btnCls} disabled={busy !== null || accounts.length === 0} onClick={() => void createBaseline()}>Create baseline version</button>
          <button className={btnCls} disabled={busy !== null || baselines.length === 0} onClick={() => void checkDrift()}>Check drift</button>
        </div>
        <p className="mt-2 text-sm text-slate-400">{baselines.map((b) => `v${b.version} (${b.hash.slice(0, 8)}…)`).join(" · ") || "No baselines yet."}</p>
        {deviations.length ? <ul className="mt-2 list-disc pl-5 text-sm text-slate-300">{deviations.map((d) => <li key={d.ruleId}>{d.ruleId}: {d.message}</li>)}</ul> : null}
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Ask the copilot (§137) — deterministic, stored data only">
          <div className="flex gap-2">
            <input className={`${inputCls} flex-1`} value={nlText} onChange={(e) => setNlText(e.target.value)} placeholder="Show public production databases" />
            <button className={btnCls} disabled={busy !== null || !nlText} onClick={() => void runNl()}>Ask</button>
          </div>
          {nlResult ? <p className="mt-2 text-sm text-slate-300">{nlResult}</p> : null}
          <p className="mt-2 text-xs text-slate-500">Change requests ("make all buckets private") are refused — the copilot produces plans, never changes (§136/§160).</p>
        </Card>
        <Card title="Steampipe approved query packs (§24) — raw SQL is rejected (§25)">
          <ul className="list-disc pl-5 text-sm text-slate-300">
            {packs.map((p) => <li key={p.id}>{p.title} ({p.provider}) — {p.queries.length} approved queries</li>)}
          </ul>
          <p className="mt-2 text-xs text-slate-500">Live execution requires the governed worker transport; packs are catalogued here and report NOT_CONFIGURED honestly until wired.</p>
        </Card>
      </div>

      <Card title="Reports (§133)">
        <ul className="list-disc pl-5 text-sm text-slate-300">
          {reports.map((r) => <li key={r.reportType}>{r.title} — <span className="text-xs text-slate-500">{r.noCertificationStatement}</span></li>)}
        </ul>
      </Card>
    </div>
  );
}
