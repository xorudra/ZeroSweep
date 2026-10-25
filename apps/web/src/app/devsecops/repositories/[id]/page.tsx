"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface RepoDetail {
  repository: Record<string, unknown>;
  link: Record<string, unknown> | null;
  policy: Record<string, unknown> | null;
  baseline: Record<string, unknown> | null;
  findingCounts: { total: number; sast: number; sca: number; secrets: number; sbom: number; container: number };
  recentPullRequestAssessments: Array<Record<string, unknown>>;
}

/**
 * Repository security detail (Prompt 24 §92): provider identity,
 * default branch, security baseline (bound to an immutable commit),
 * per-kind finding counts, the repository security policy, and
 * recent PR/MR assessments with gate outcomes.
 */
export default function Page() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<RepoDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!params?.id) return;
    apiFetch<RepoDetail>(`/devsecops/repositories/${params.id}`).then(setData).catch((e: Error) => setError(e.message));
  }, [params?.id]);

  if (error) return <p className="text-sm text-red-300">{error}</p>;
  if (!data) return <p className="text-sm text-slate-400">Loading…</p>;
  const repo = data.repository;
  const policy = data.policy ?? {};
  const flag = (v: unknown) => (v === true ? "On" : "Off");

  return (
    <>
      <PageHeader eyebrow="DevSecOps · Repository" title={String(repo.name ?? "Repository")} body={String(repo.remoteUrl ?? "")} />
      <div className="space-y-6">
        <Card>
          <h2 className="text-base font-semibold text-slate-100">Security posture</h2>
          <dl className="mt-3 grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
            <div><dt className="text-slate-500">Provider</dt><dd className="text-slate-200">{String(data.link?.provider ?? repo.provider ?? "—")}</dd></div>
            <div><dt className="text-slate-500">Default branch</dt><dd className="text-slate-200">{String(repo.defaultBranch ?? "—")}</dd></div>
            <div><dt className="text-slate-500">Baseline commit</dt><dd className="text-slate-200">{data.baseline ? String(data.baseline.commitSha ?? "").slice(0, 12) : "No baseline captured"}</dd></div>
            <div><dt className="text-slate-500">Findings</dt><dd className="text-slate-200">{data.findingCounts.total}</dd></div>
            <div><dt className="text-slate-500">SAST / SCA</dt><dd className="text-slate-200">{data.findingCounts.sast} / {data.findingCounts.sca}</dd></div>
            <div><dt className="text-slate-500">Secrets / SBOM / Container</dt><dd className="text-slate-200">{data.findingCounts.secrets} / {data.findingCounts.sbom} / {data.findingCounts.container}</dd></div>
          </dl>
        </Card>
        <Card>
          <h2 className="text-base font-semibold text-slate-100">Repository security policy</h2>
          <dl className="mt-3 grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
            <div><dt className="text-slate-500">Scan on push</dt><dd className="text-slate-200">{flag(policy.scanOnPush)}</dd></div>
            <div><dt className="text-slate-500">Scan on PR/MR</dt><dd className="text-slate-200">{flag(policy.scanOnPullRequest)}</dd></div>
            <div><dt className="text-slate-500">Scan default branch</dt><dd className="text-slate-200">{flag(policy.scanDefaultBranch)}</dd></div>
            <div><dt className="text-slate-500">SAST / SCA / Secrets / SBOM</dt><dd className="text-slate-200">{flag(policy.sastEnabled)} / {flag(policy.scaEnabled)} / {flag(policy.secretScanEnabled)} / {flag(policy.sbomEnabled)}</dd></div>
            <div><dt className="text-slate-500">Container scanning</dt><dd className="text-slate-200">{flag(policy.containerScanEnabled)}</dd></div>
            <div><dt className="text-slate-500">PR gate preset</dt><dd className="text-slate-200">{String(policy.prGatePreset ?? "—")}</dd></div>
          </dl>
          <p className="mt-3 text-xs text-slate-500">
            Even with every trigger on, a scan starts only when the linked target is VERIFIED and an APPROVED assessment already exists.
          </p>
        </Card>
        <Card>
          <h2 className="text-base font-semibold text-slate-100">Recent PR/MR assessments</h2>
          {data.recentPullRequestAssessments.length === 0 ? (
            <p className="mt-2 text-sm text-slate-500">None yet.</p>
          ) : (
            <ul className="mt-2 space-y-2 text-sm">
              {data.recentPullRequestAssessments.map((a, i) => (
                <li key={i} className="flex items-center gap-3">
                  <span className="text-slate-300">#{String(a.prNumber ?? "")}</span>
                  <span className="text-slate-200">{String(a.title ?? "")}</span>
                  <span className="text-slate-500">{String(a.headBranch ?? "")} → {String(a.baseBranch ?? "")}</span>
                  <Badge tone={a.gateResult === "PASS" ? "ok" : a.gateResult === "FAIL" ? "critical" : "neutral"}>{String(a.gateResult ?? a.scanStatus ?? "—")}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
