"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Mobile build detail (Prompt 17 §95): version, build number,
 * SHA-256, signing metadata, SDK/OS targets, permissions,
 * components, findings, SBOM, extracted endpoints and the quality
 * gate (§90). Extracted endpoints are DISCOVERED_REFERENCE — they
 * never authorize targets and never expand scope (§29/§30).
 * Findings show OWASP Mobile + MASVS mappings and whether dynamic
 * evidence confirmed a static observation (§88/§97).
 */
interface BuildData {
  id: string; applicationId: string; applicationName: string; platform: string;
  versionName?: string | null; versionCode?: number | null; buildNumber?: string | null;
  artifactHash: string; artifactFormat: string; artifactSizeBytes: string; status: string;
  signingMetadata: Record<string, unknown>; minOsVersion?: string | null; targetOsVersion?: string | null;
  architectures: string[]; findings: number; components: number; qualityGate?: { gateName: string; status: string } | null;
  deepLinks: Array<{ id: string; scheme: string; host?: string | null; pathPrefix?: string | null; autoVerify: boolean }>;
  nativeLibraries: Array<{ id: string; path: string; architecture?: string | null; pie?: boolean | null; nx?: boolean | null; stackCanary?: boolean | null; relro?: string | null }>;
  sboms: Array<{ id: string; format: string; componentCount: number }>;
}
interface FindingRow {
  id: string; title: string; severity: string; status: string; ruleId?: string | null;
  mobileFindingType?: string | null; owaspMobile?: string | null; masvsControl?: string | null;
  cwe?: string | null; mobileComponent?: string | null; sources: string[]; dynamicConfirmed: boolean;
}
interface EndpointRow { id: string; url: string; host: string; kind: string; classification: string; source: string; linkedAssetId?: string | null }

export default function Page() {
  const params = useParams<{ id: string }>();
  const [build, setBuild] = useState<BuildData | null>(null);
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [b, f, e] = await Promise.all([
        apiFetch<BuildData>(`/mobile/builds/${params.id}`),
        apiFetch<{ items: FindingRow[] }>(`/mobile/builds/${params.id}/findings`),
        apiFetch<{ items: EndpointRow[] }>(`/mobile/builds/${params.id}/endpoints`),
      ]);
      setBuild(b);
      setFindings(f.items);
      setEndpoints(e.items);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load build");
      setState("error");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const yn = (v?: boolean | null) => (v === null || v === undefined ? "—" : v ? "yes" : "no");

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Mobile Security" title={build ? `${build.applicationName} — build ${build.versionName ?? ""}` : "Build"} body="Build identity, inventory, findings and quality gate." />
      <Link href="/mobile-security" className="text-sm text-indigo-300 hover:underline">← Mobile Security</Link>
      {state === "error" && <p className="text-sm text-red-400">{error}</p>}
      {build && (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Card><p className="text-sm text-slate-400">SHA-256</p><p className="break-all font-mono text-xs text-slate-100">{build.artifactHash}</p></Card>
            <Card><p className="text-sm text-slate-400">Format / size</p><p className="text-slate-100">{build.artifactFormat} · {build.artifactSizeBytes} bytes</p></Card>
            <Card><p className="text-sm text-slate-400">OS targets</p><p className="text-slate-100">min {build.minOsVersion ?? "—"} · target {build.targetOsVersion ?? "—"}</p></Card>
            <Card><p className="text-sm text-slate-400">Quality gate (§90)</p><p className="text-slate-100">{build.qualityGate ? `${build.qualityGate.gateName}: ${build.qualityGate.status}` : "Not evaluated"}</p></Card>
          </div>

          <Card>
            <h2 className="mb-2 text-lg font-medium text-slate-100">Signing &amp; platform</h2>
            <p className="text-sm text-slate-300">Platform: {build.platform} · Architectures: {build.architectures.join(", ") || "—"} · Status: {build.status}</p>
            <pre className="mt-2 overflow-x-auto rounded bg-slate-900 p-3 font-mono text-xs text-slate-300">{JSON.stringify(build.signingMetadata, null, 2)}</pre>
            <p className="mt-2 text-xs text-slate-500">Certificate findings exist only on real chain/expiry/debug-key evidence — never from a certificate's name (§25). Signing keys are never stored; references only.</p>
            <Link href={`/mobile-security/builds/${build.id}/manifest`} className="mt-2 inline-block text-sm text-indigo-300 hover:underline">View manifest / plist analysis (§96) →</Link>
          </Card>

          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <h2 className="mb-2 text-lg font-medium text-slate-100">Deep links</h2>
              {build.deepLinks.length === 0 && <EmptyState title="No deep links" body="Scheme/host presence alone is not a vulnerability (§22)." />}
              <ul className="space-y-1 text-sm text-slate-300">
                {build.deepLinks.map((d) => <li key={d.id}><span className="font-mono">{d.scheme}://{d.host ?? ""}{d.pathPrefix ?? ""}</span> {d.autoVerify && <Badge>autoVerify</Badge>}</li>)}
              </ul>
            </Card>
            <Card>
              <h2 className="mb-2 text-lg font-medium text-slate-100">Native libraries (§36)</h2>
              {build.nativeLibraries.length === 0 && <EmptyState title="No native libraries recorded" body="Hardening facts (PIE/NX/canary/RELRO) appear after binary analysis." />}
              <ul className="space-y-1 text-sm text-slate-300">
                {build.nativeLibraries.map((l) => (
                  <li key={l.id}><span className="font-mono text-xs">{l.path}</span> · {l.architecture ?? "—"} · PIE {yn(l.pie)} · NX {yn(l.nx)} · canary {yn(l.stackCanary)} · RELRO {l.relro ?? "—"}</li>
                ))}
              </ul>
            </Card>
          </div>

          <Card>
            <h2 className="mb-2 text-lg font-medium text-slate-100">SBOM (§44)</h2>
            {build.sboms.length === 0
              ? <p className="text-sm text-slate-400">No SBOM yet — component versions are never invented; unknown versions stay unknown (§45).</p>
              : <ul className="text-sm text-slate-300">{build.sboms.map((s) => <li key={s.id}>{s.format} · {s.componentCount} components</li>)}</ul>}
          </Card>

          <Card>
            <h2 className="mb-3 text-lg font-medium text-slate-100">Findings (§97)</h2>
            {findings.length === 0 && <EmptyState title="No findings" body="Static + dynamic observations deduplicate to one canonical finding per issue (§51)." />}
            <div className="space-y-2">
              {findings.map((f) => (
                <div key={f.id} className="rounded bg-slate-900 px-3 py-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-slate-100">{f.title}</span>
                    <Badge>{f.severity}</Badge>
                    <Badge>{f.status}</Badge>
                    {f.dynamicConfirmed && <Badge>dynamic confirmed</Badge>}
                  </div>
                  <p className="mt-1 text-xs text-slate-400">
                    {f.ruleId ?? ""} · {f.mobileFindingType ?? ""} · OWASP Mobile {f.owaspMobile ?? "—"} · {f.masvsControl ?? "no MASVS mapping"} · {f.cwe ?? ""}
                    {f.mobileComponent ? ` · component: ${f.mobileComponent}` : ""} · sources: {f.sources.join(", ")}
                  </p>
                </div>
              ))}
            </div>
          </Card>

          <Card>
            <h2 className="mb-3 text-lg font-medium text-slate-100">Extracted endpoints (§29)</h2>
            {endpoints.length === 0 && <EmptyState title="No endpoints extracted" body="URLs/hosts found in the app appear here as references." />}
            <ul className="space-y-1 text-sm">
              {endpoints.map((e) => (
                <li key={e.id} className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-slate-200">{e.url}</span>
                  <Badge>{e.classification}</Badge>
                  <span className="text-xs text-slate-500">via {e.source}{e.linkedAssetId ? " · linked to an existing in-scope asset" : ""}</span>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-slate-500">DISCOVERED_REFERENCE: an extracted endpoint is never automatically authorized and never expands assessment scope.</p>
          </Card>
        </>
      )}
    </div>
  );
}
