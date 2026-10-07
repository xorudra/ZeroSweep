"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Domain detail (Prompt 15 §91): posture summary, domain controllers,
 * trusts, group policies, snapshots and findings rollup. The
 * credential profile shows the REFERENCE NAME only — a credential
 * value is never displayed anywhere in this product (§7).
 */
interface DomainDetail {
  id: string; dnsName: string; netbiosName?: string | null; domainSid?: string | null;
  functionalLevel?: string | null; environment: string; criticality: string; status: string;
  credentialProfile: { name: string; identityKind: string; credentialReference: string | null; credentialConfigured: boolean } | null;
  controllers: Array<{ id: string; hostname: string; dnsName?: string | null; ipAddresses: string[]; osName?: string | null; services: Record<string, unknown> }>;
  trusts: Array<{ id: string; targetDomainName: string; direction: string; trustType: string; transitive: boolean; sidFilteringEnabled?: boolean | null; selectiveAuthentication?: boolean | null }>;
  groupPolicies: Array<{ id: string; name: string; linkedTo: string[] }>;
  latestSnapshots: Array<{ id: string; collectionProfile: string; snapshotHash: string; relationshipCount: number; capturedAt: string }>;
  counts: { users: number; groups: number; computers: number; relationships: number; attackPaths: number; driftEvents: number };
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [domain, setDomain] = useState<DomainDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setDomain(await apiFetch<DomainDetail>(`/ad/domains/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the domain.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!domain) return <p className="text-sm text-slate-400">Loading…</p>;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Domain Detail" title={domain.dnsName} body={`Domain detail — ${domain.environment} · criticality ${domain.criticality} · assessment policy READ_ONLY`} />
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {[
          ["Status", domain.status], ["Functional level", domain.functionalLevel ?? "—"],
          ["Users", domain.counts.users], ["Groups", domain.counts.groups],
          ["Computers", domain.counts.computers], ["Relationships", domain.counts.relationships],
          ["Attack paths (modeled)", domain.counts.attackPaths], ["Drift events", domain.counts.driftEvents],
          ["Domain SID", domain.domainSid ?? "—"],
        ].map(([label, value]) => (
          <Card key={label as string}>
            <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
            <p className="text-lg font-semibold text-slate-100 break-all">{value}</p>
          </Card>
        ))}
      </div>

      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Assessment identity</h2>
        {domain.credentialProfile ? (
          <p className="text-sm text-slate-300">
            {domain.credentialProfile.name} · kind {domain.credentialProfile.identityKind} · reference{" "}
            <span className="font-mono">{domain.credentialProfile.credentialReference ?? "not configured"}</span>{" "}
            <Badge>{domain.credentialProfile.credentialConfigured ? "CONFIGURED" : "NOT_CONFIGURED"}</Badge>
            <span className="block text-xs text-slate-500 mt-1">Reference name only — the value is resolved inside the DIRECTORY_ANALYSIS worker under a job-scoped lease and is never shown here.</span>
          </p>
        ) : (
          <EmptyState title="No credential profile" body="Scans of this domain report NOT_CONFIGURED until a read-only assessment identity reference is registered." />
        )}
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Domain controllers (approved collection targets, §11)</h2>
        {domain.controllers.length === 0 ? <EmptyState title="No controllers recorded" body="Only explicitly approved domain controllers are ever contacted." /> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Host</th><th>IPs</th><th>OS</th><th>Service posture</th></tr></thead>
            <tbody>
              {domain.controllers.map((c) => (
                <tr key={c.id} className="border-t border-slate-800">
                  <td className="py-1.5">{c.dnsName ?? c.hostname}</td>
                  <td>{(c.ipAddresses ?? []).join(", ")}</td>
                  <td>{c.osName ?? "—"}</td>
                  <td className="text-xs text-slate-400">
                    {Object.entries(c.services ?? {}).map(([k, v]) => `${k}: ${String(v)}`).join(" · ") || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <div className="grid md:grid-cols-2 gap-3">
        <Card>
          <h2 className="text-base font-semibold text-slate-100 mb-2">Trusts</h2>
          {domain.trusts.length === 0 ? <EmptyState title="No trusts recorded" body="Trusts appear after collection." /> : (
            <ul className="text-sm space-y-1">
              {domain.trusts.map((t) => (
                <li key={t.id} className="text-slate-300">
                  {t.targetDomainName} · {t.direction} · {t.trustType} · transitive {String(t.transitive)} ·
                  SID filtering {t.sidFilteringEnabled === null || t.sidFilteringEnabled === undefined ? "unknown" : String(t.sidFilteringEnabled)} ·
                  selective auth {t.selectiveAuthentication === null || t.selectiveAuthentication === undefined ? "unknown" : String(t.selectiveAuthentication)}
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card>
          <h2 className="text-base font-semibold text-slate-100 mb-2">Group policies</h2>
          {domain.groupPolicies.length === 0 ? <EmptyState title="No GPOs recorded" body="Group Policy objects appear after collection." /> : (
            <ul className="text-sm space-y-1">
              {domain.groupPolicies.map((g) => (
                <li key={g.id} className="text-slate-300">{g.name} <span className="text-slate-500">linked to {(g.linkedTo ?? []).join(", ") || "—"}</span></li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Latest snapshots</h2>
        {domain.latestSnapshots.length === 0 ? <EmptyState title="No snapshots yet" body="Each collection records a content-hashed snapshot for drift comparison." /> : (
          <ul className="text-sm space-y-1">
            {domain.latestSnapshots.map((s) => (
              <li key={s.id} className="text-slate-300">
                {s.collectionProfile} · {s.relationshipCount} relationships · hash <span className="font-mono text-xs">{s.snapshotHash.slice(0, 16)}…</span> · {new Date(s.capturedAt).toLocaleString()}
              </li>
            ))}
          </ul>
        )}
        <p className="text-sm mt-3">
          <Link className="text-indigo-300 hover:underline" href="/active-directory/attack-paths">View modeled attack paths</Link>
          {" · "}
          <Link className="text-indigo-300 hover:underline" href="/active-directory/drift">View drift</Link>
        </p>
      </Card>
    </div>
  );
}
