"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface DevSecOpsData {
  repositories: Array<{ link: Record<string, unknown>; repository: Record<string, unknown> | null }>;
  recentPipelineRuns: Array<Record<string, unknown>>;
  recentPullRequestAssessments: Array<Record<string, unknown>>;
}

function gateBadge(result: unknown) {
  const r = String(result ?? "—");
  const tone = r === "PASS" ? "ok" : r === "FAIL" ? "critical" : r === "WARN" ? "high" : "neutral";
  return <Badge tone={tone as never}>{r}</Badge>;
}

/**
 * DevSecOps security dashboard (Prompt 24 §91): linked repositories,
 * recent PR/MR security assessments, pipeline runs and quality-gate
 * outcomes. Everything here is read from governed platform records —
 * a gate verdict exists only because a real scan produced it.
 */
export default function Page() {
  const [data, setData] = useState<DevSecOpsData | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<DevSecOpsData>("/devsecops/repositories").then(setData).catch((e: Error) => setError(e.message));
  }, []);

  return (
    <>
      <PageHeader
        eyebrow="DevSecOps"
        title="DevSecOps Security"
        body="Repositories linked to GitHub, GitLab and Bitbucket; PR/MR security assessments; CI pipeline gate verdicts. Webhooks can only trigger scans of verified targets under already-approved assessments — they can never approve anything."
      />
      {error ? <p className="text-sm text-red-300">{error}</p> : null}
      {!data && !error ? <p className="text-sm text-slate-400">Loading…</p> : null}
      {data ? (
        <div className="space-y-6">
          <Card>
            <h2 className="text-base font-semibold text-slate-100">Repositories</h2>
            {data.repositories.length === 0 ? (
              <EmptyState title="No linked repositories" body="Connect a source-control integration and sync — repositories appear here as staging records until they are linked to governed targets." />
            ) : (
              <table className="mt-3 w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-400">
                    <th className="px-2 py-1">Repository</th><th className="px-2 py-1">Provider</th>
                    <th className="px-2 py-1">Default branch</th><th className="px-2 py-1">Visibility</th><th className="px-2 py-1">Last sync</th>
                  </tr>
                </thead>
                <tbody>
                  {data.repositories.map(({ link, repository }, i) => (
                    <tr key={i} className="border-t border-slate-800">
                      <td className="px-2 py-2">
                        {repository ? (
                          <Link href={`/devsecops/repositories/${String(repository.id)}`} className="text-sky-300 hover:underline">
                            {String(repository.name ?? link.externalRepositoryRef ?? "")}
                          </Link>
                        ) : String(link.externalRepositoryRef ?? "")}
                      </td>
                      <td className="px-2 py-2 text-slate-300">{String(link.provider ?? "")}</td>
                      <td className="px-2 py-2 text-slate-300">{String(link.defaultBranch ?? "—")}</td>
                      <td className="px-2 py-2 text-slate-300">{String(link.visibility ?? "—")}</td>
                      <td className="px-2 py-2 text-slate-300">{link.lastSyncedAt ? new Date(String(link.lastSyncedAt)).toLocaleString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <Card>
            <h2 className="text-base font-semibold text-slate-100">Recent PR/MR assessments</h2>
            {data.recentPullRequestAssessments.length === 0 ? (
              <p className="mt-2 text-sm text-slate-500">No pull-request assessments yet. Signed PR webhooks create them when the repository policy enables PR scans.</p>
            ) : (
              <table className="mt-3 w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-400">
                    <th className="px-2 py-1">PR</th><th className="px-2 py-1">Title</th><th className="px-2 py-1">Scan</th><th className="px-2 py-1">Gate</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recentPullRequestAssessments.map((a, i) => (
                    <tr key={i} className="border-t border-slate-800">
                      <td className="px-2 py-2 text-slate-300">#{String(a.prNumber ?? "")}</td>
                      <td className="px-2 py-2 text-slate-200">{String(a.title ?? "")}</td>
                      <td className="px-2 py-2 text-slate-300">{String(a.scanStatus ?? "")}</td>
                      <td className="px-2 py-2">{gateBadge(a.gateResult)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>

          <Card>
            <h2 className="text-base font-semibold text-slate-100">Recent pipeline runs</h2>
            {data.recentPipelineRuns.length === 0 ? (
              <p className="mt-2 text-sm text-slate-500">No pipeline runs yet. CI systems request runs with a scoped API key (pipelines:security-scan) and read verdicts with pipelines:gate-read.</p>
            ) : (
              <table className="mt-3 w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-400">
                    <th className="px-2 py-1">Pipeline</th><th className="px-2 py-1">Provider</th><th className="px-2 py-1">Commit</th><th className="px-2 py-1">Status</th><th className="px-2 py-1">Gate</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recentPipelineRuns.map((r, i) => (
                    <tr key={i} className="border-t border-slate-800">
                      <td className="px-2 py-2 text-slate-200">{String(r.externalPipelineId ?? "")}</td>
                      <td className="px-2 py-2 text-slate-300">{String(r.provider ?? "")}</td>
                      <td className="px-2 py-2 text-slate-300">{String(r.commitSha ?? "").slice(0, 10)}</td>
                      <td className="px-2 py-2 text-slate-300">{String(r.status ?? "")}{r.blockReason ? ` (${String(r.blockReason)})` : ""}</td>
                      <td className="px-2 py-2">{gateBadge(r.gateResult)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      ) : null}
    </>
  );
}
