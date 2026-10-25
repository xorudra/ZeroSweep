"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card } from "@dsrclone/ui";

/**
 * Manifest / plist view (Prompt 17 §96): the extracted analysis
 * artifacts for a build. Access requires VIEW_MOBILE_SOURCE_
 * ARTIFACTS and every access is audited (MOBILE_ARTIFACT_ACCESSED,
 * §116). All strings render as inert text — hostile manifest or
 * plist content can never execute or inject markup here (§108).
 * Decompiled source is never executed anywhere in ZeroSweep (§19).
 */
interface ArtifactsData {
  buildId: string; artifactHash: string;
  analysisArtifacts: Record<string, unknown>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<ArtifactsData | null>(null);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const d = await apiFetch<ArtifactsData>(`/mobile/builds/${params.id}/artifacts`);
      setData(d);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load artifacts");
      setState("error");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const manifest = typeof data?.analysisArtifacts?.manifestXml === "string" ? (data.analysisArtifacts.manifestXml as string) : null;
  const plist = typeof data?.analysisArtifacts?.infoPlistXml === "string" ? (data.analysisArtifacts.infoPlistXml as string) : null;
  const nsc = typeof data?.analysisArtifacts?.networkSecurityConfigXml === "string" ? (data.analysisArtifacts.networkSecurityConfigXml as string) : null;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Mobile Security" title="Manifest analysis" body="Sanitized manifest / plist / network-security-config artifacts for this build." />
      <Link href={`/mobile-security/builds/${params.id}`} className="text-sm text-indigo-300 hover:underline">← Build detail</Link>
      {state === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state === "error" && (
        <Card>
          <p className="text-sm text-red-400">{error}</p>
          <p className="mt-2 text-xs text-slate-500">Source artifacts are restricted to OWNER / ADMIN / SECURITY_ENGINEER and every access is audited (§24/§101/§116).</p>
        </Card>
      )}
      {data && (
        <>
          <p className="font-mono text-xs text-slate-400">SHA-256 {data.artifactHash}</p>
          {manifest && (
            <Card>
              <h2 className="mb-2 text-lg font-medium text-slate-100">AndroidManifest.xml</h2>
              <pre className="max-h-[480px] overflow-auto rounded bg-slate-900 p-3 font-mono text-xs text-slate-300">{manifest}</pre>
            </Card>
          )}
          {nsc && (
            <Card>
              <h2 className="mb-2 text-lg font-medium text-slate-100">network_security_config.xml</h2>
              <pre className="max-h-[320px] overflow-auto rounded bg-slate-900 p-3 font-mono text-xs text-slate-300">{nsc}</pre>
            </Card>
          )}
          {plist && (
            <Card>
              <h2 className="mb-2 text-lg font-medium text-slate-100">Info.plist</h2>
              <pre className="max-h-[480px] overflow-auto rounded bg-slate-900 p-3 font-mono text-xs text-slate-300">{plist}</pre>
            </Card>
          )}
          {!manifest && !plist && !nsc && (
            <Card><p className="text-sm text-slate-400">No manifest/plist artifacts recorded for this build yet — they appear after static analysis.</p></Card>
          )}
          <p className="text-xs text-slate-500">An exported component is inventoried, not automatically a vulnerability; a dangerous permission is classified, not auto-flagged (§20/§21). Rendering is text-only: hostile strings stay inert (§108).</p>
        </>
      )}
    </div>
  );
}
