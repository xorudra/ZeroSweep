"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Binary artifact detail (Prompt 18 §86). Identity, hardening
 * profile with per-mitigation explanation + remediation, sections,
 * dependencies, findings, SBOMs and the governed debug-session
 * records. Extracted references are DISCOVERED_REFERENCE only —
 * listed for review, never scanned, never scope (§31). There is NO
 * unrestricted debugger console here (§89): sessions are governed
 * records with typed operations and a separate approver.
 */
interface HardeningEntry { name: string; status: string; evidence?: string; source?: string }
interface FindingRow {
  id: string; title: string; severity: string; status: string; binaryFindingType?: string | null;
  ruleId?: string | null; cwe?: string | null; cve?: string | null; binaryComponent?: string | null;
  binaryReachability?: string | null; staticConfidence?: string | null; sources: string[];
}
interface Detail {
  id: string; name: string; source: string; sha256: string; sha1?: string | null; sizeBytes: string;
  format: string; architecture?: string | null; bits?: number | null; environment: string; status: string;
  sections: Array<{ name: string; type?: string | null; size: string; permissions?: string | null; entropy?: number | null; source: string }>;
  counts: { functions: number; imports: number; exports: number };
  dependencies: Array<{ id: string; library: string; version?: string | null; purl?: string | null; sourceKind: string; source: string }>;
  hardening: HardeningEntry[];
  findings: FindingRow[];
  debugSessions: Array<{ id: string; status: string; requestedBy: string; approvedBy?: string | null; networkPolicy: string; timeoutSeconds: number; createdAt?: string | null }>;
  sboms: Array<{ id: string; format: string; specVersion: string; checksum: string; componentCount: number }>;
}
interface ArtifactLite { id: string; name: string; sha256: string }

const HARDENING_GUIDE: Record<string, { explanation: string; remediation: string }> = {
  NX: { explanation: "Non-executable stack/heap — injected data cannot run as code.", remediation: "Link with a non-executable stack (-Wl,-z,noexecstack / NX_COMPAT)." },
  PIE: { explanation: "Position-independent executable — ASLR can randomize the load base.", remediation: "Build with -fPIE -pie." },
  RELRO: { explanation: "Read-only relocations — the GOT is remapped read-only after relocation (FULL adds BIND_NOW).", remediation: "Link with -Wl,-z,relro,-z,now." },
  STACK_CANARY: { explanation: "Stack protector canaries detect stack-smashing before return.", remediation: "Compile with -fstack-protector-strong." },
  FORTIFY: { explanation: "FORTIFY_SOURCE replaces unsafe libc calls with checked variants.", remediation: "Compile with -D_FORTIFY_SOURCE=3 -O2." },
  ASLR: { explanation: "Address space layout randomization support (PE: /DYNAMICBASE).", remediation: "Link with /DYNAMICBASE." },
  CFG: { explanation: "Control Flow Guard validates indirect call targets (PE).", remediation: "Compile/link with /guard:cf." },
  SAFESEH: { explanation: "Safe exception-handler table (PE, 32-bit).", remediation: "Link with /SAFESEH." },
  CODE_SIGNING: { explanation: "Authenticode / platform code signature present.", remediation: "Sign release artifacts and verify signatures at intake." },
};

const PROFILES = ["BINARY_METADATA_ONLY", "BINARY_BASELINE", "BINARY_ASSESSMENT", "BINARY_COMPREHENSIVE_STATIC", "BINARY_DEPENDENCY_ANALYSIS", "BINARY_CONTROLLED_DEBUG"] as const;
const DEBUG_OPS = ["START_APPROVED_FIXTURE", "SET_APPROVED_BREAKPOINT", "INSPECT_REGISTER_METADATA", "INSPECT_BOUNDED_MEMORY", "CAPTURE_CRASH_METADATA", "TERMINATE_SESSION"] as const;
const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [artifacts, setArtifacts] = useState<ArtifactLite[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [profile, setProfile] = useState<string>("BINARY_BASELINE");
  const [diffTarget, setDiffTarget] = useState("");
  const [debugOp, setDebugOp] = useState<string>("START_APPROVED_FIXTURE");

  const load = useCallback(async () => {
    try {
      const [d, all] = await Promise.all([
        apiFetch<Detail>(`/binaries/${params.id}`),
        apiFetch<{ items: ArtifactLite[] }>("/binaries"),
      ]);
      setDetail(d);
      setArtifacts(all.items.filter((a) => a.id !== params.id));
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load artifact");
      setState("error");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const startScan = async () => {
    setBusy("scan"); setNotice("");
    try {
      const res = await apiFetch<{ scanId: string }>(`/binaries/${params.id}/scan`, { method: "POST", body: JSON.stringify({ profile }) });
      setNotice(`Scan ${res.scanId} queued under profile ${profile}. Static analysis only — the artifact is parsed, never executed.`);
      await load();
    } catch (e) { setNotice(e instanceof ApiError ? e.message : "Scan start failed"); } finally { setBusy(null); }
  };

  const createDiff = async () => {
    if (!diffTarget) return;
    setBusy("diff"); setNotice("");
    try {
      const res = await apiFetch<{ id: string }>("/binary-diffs", {
        method: "POST", body: JSON.stringify({ baseArtifactId: params.id, targetArtifactId: diffTarget }),
      });
      router.push(`/binary-security/diffs/${res.id}`);
    } catch (e) { setNotice(e instanceof ApiError ? e.message : "Diff failed"); setBusy(null); }
  };

  const requestDebug = async () => {
    setBusy("debug"); setNotice("");
    try {
      const res = await apiFetch<{ status: string; reasons?: string[] }>(`/binaries/${params.id}/debug-sessions`, {
        method: "POST", body: JSON.stringify({ operations: [{ operation: debugOp }], networkPolicy: "NO_NETWORK" }),
      });
      setNotice(`Debug session ${res.status}. LAB artifacts only, separate approver required, typed operations only — no console exists.`);
      await load();
    } catch (e) { setNotice(e instanceof ApiError ? e.message : "Debug request failed"); } finally { setBusy(null); }
  };

  if (state === "loading") return <p className="text-sm text-slate-400">Loading artifact…</p>;
  if (state === "error" || !detail) return <p className="text-sm text-red-400">{error || "Artifact not found"}</p>;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Binary Security" title={detail.name} body="Artifact detail — every read of this record is audited (§84). Static evidence only; reachability is an evidence state, never a claim of exploitability (§62)." />
      {notice && <p className="text-sm text-amber-300">{notice}</p>}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card><p className="text-sm text-slate-400">Format</p><p className="text-xl font-semibold text-slate-100">{detail.format}</p><p className="text-xs text-slate-500">{detail.architecture ?? "—"} · {detail.bits ?? "—"}-bit</p></Card>
        <Card><p className="text-sm text-slate-400">Functions</p><p className="text-xl font-semibold text-slate-100">{detail.counts.functions}</p><p className="text-xs text-slate-500">{detail.counts.imports} imports · {detail.counts.exports} exports</p></Card>
        <Card><p className="text-sm text-slate-400">Dependencies</p><p className="text-xl font-semibold text-slate-100">{detail.dependencies.length}</p><p className="text-xs text-slate-500">versions only where evidence exists (§25)</p></Card>
        <Card><p className="text-sm text-slate-400">Findings</p><p className="text-xl font-semibold text-slate-100">{detail.findings.length}</p><p className="text-xs text-slate-500">{detail.environment} · {detail.status}</p></Card>
      </div>

      <Card>
        <h2 className="mb-2 text-lg font-medium text-slate-100">Identity</h2>
        <p className="break-all font-mono text-xs text-slate-300">SHA-256 {detail.sha256}</p>
        {detail.sha1 && <p className="break-all font-mono text-xs text-slate-500">SHA-1 {detail.sha1} (interoperability only)</p>}
        <p className="mt-1 text-xs text-slate-500">{detail.sizeBytes} bytes · source {detail.source}</p>
        <div className="mt-3 flex flex-wrap items-end gap-2">
          <label className="text-sm text-slate-400">Profile
            <select className={`${inputCls} ml-2`} value={profile} onChange={(e) => setProfile(e.target.value)}>
              {PROFILES.map((p) => <option key={p}>{p}</option>)}
            </select>
          </label>
          <button disabled={busy !== null} onClick={() => void startScan()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">Start static scan</button>
          <Link href={`/binary-security/${detail.id}/functions`} className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700">Function explorer</Link>
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Hardening profile (§16)</h2>
        {detail.hardening.length === 0 && <EmptyState title="No hardening profile yet" body="Run BINARY_BASELINE — checksec + platform header analysis produce the profile as observations with evidence." />}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead><tr className="text-slate-400"><th className="py-1 pr-3">Mitigation</th><th className="py-1 pr-3">State</th><th className="py-1 pr-3">What it means</th><th className="py-1">Remediation</th></tr></thead>
            <tbody>
              {detail.hardening.map((h) => (
                <tr key={h.name} className="border-t border-slate-800 align-top">
                  <td className="py-1.5 pr-3 text-slate-200">{h.name}</td>
                  <td className="py-1.5 pr-3"><Badge>{h.status}</Badge></td>
                  <td className="py-1.5 pr-3 text-slate-400">{HARDENING_GUIDE[h.name]?.explanation ?? h.evidence ?? "Observed from headers/tool evidence."}</td>
                  <td className="py-1.5 text-slate-400">{HARDENING_GUIDE[h.name]?.remediation ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-xs text-slate-500">States are OBSERVATIONS from headers and tool evidence — never certification claims. PE-only mitigations read NOT_APPLICABLE on ELF and vice versa.</p>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-lg font-medium text-slate-100">Sections</h2>
          {detail.sections.length === 0 && <EmptyState title="No sections recorded" body="Sections arrive with the metadata extraction stage." />}
          <div className="space-y-1">
            {detail.sections.map((s) => (
              <div key={s.name} className="flex items-center justify-between rounded bg-slate-900 px-3 py-1.5 text-sm">
                <span className="font-mono text-slate-200">{s.name}</span>
                <span className="text-xs text-slate-400">{s.permissions ?? "—"} · {s.size} B · entropy {s.entropy ?? "—"}</span>
              </div>
            ))}
          </div>
        </Card>
        <Card>
          <h2 className="mb-3 text-lg font-medium text-slate-100">Dependencies (§25–§27)</h2>
          {detail.dependencies.length === 0 && <EmptyState title="No dependencies recorded" body="Dynamically-linked libraries appear after metadata extraction." />}
          <div className="space-y-1">
            {detail.dependencies.map((d) => (
              <div key={d.id} className="flex items-center justify-between rounded bg-slate-900 px-3 py-1.5 text-sm">
                <span className="font-mono text-slate-200">{d.library}</span>
                <span className="text-xs text-slate-400">{d.version ? `v${d.version}` : "version unknown — never inferred"} · {d.source}</span>
              </div>
            ))}
          </div>
          {detail.sboms.length > 0 && (
            <p className="mt-3 text-xs text-slate-500">SBOMs: {detail.sboms.map((s) => `${s.format} (${s.componentCount} components, ${s.checksum.slice(0, 8)}…)`).join(" · ")}</p>
          )}
        </Card>
      </div>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Findings</h2>
        {detail.findings.length === 0 && <EmptyState title="No findings" body="Findings appear after a scan — multi-tool duplicates are correlated into one canonical finding with every observation preserved." />}
        <div className="space-y-2">
          {detail.findings.map((f) => (
            <div key={f.id} className="rounded bg-slate-900 px-3 py-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-medium text-slate-100">{f.title}</span>
                <div className="flex gap-2"><Badge>{f.severity}</Badge><Badge>{f.status}</Badge></div>
              </div>
              <p className="text-xs text-slate-400">{f.binaryFindingType ?? "—"} · {f.ruleId ?? "—"} · {f.cwe ?? f.cve ?? ""} · component {f.binaryComponent ?? "—"} · reachability {f.binaryReachability ?? "UNKNOWN"} · static confidence {f.staticConfidence ?? "—"} · sources {f.sources.join(", ")}</p>
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-lg font-medium text-slate-100">Cross-build diff (§53)</h2>
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-sm text-slate-400">Compare against
              <select className={`${inputCls} ml-2`} value={diffTarget} onChange={(e) => setDiffTarget(e.target.value)}>
                <option value="">Select artifact…</option>
                {artifacts.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.sha256.slice(0, 8)}…)</option>)}
              </select>
            </label>
            <button disabled={busy !== null || !diffTarget} onClick={() => void createDiff()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">Create diff</button>
          </div>
          <p className="mt-2 text-xs text-slate-500">Diffs key functions by stable fingerprint — never by absolute address alone. Regressions (hardening removed, vulnerable dependency introduced, finding reappeared) are flagged explicitly.</p>
        </Card>
        <Card>
          <h2 className="mb-3 text-lg font-medium text-slate-100">Debug sessions — governed LAB only (§64)</h2>
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-sm text-slate-400">Typed operation
              <select className={`${inputCls} ml-2`} value={debugOp} onChange={(e) => setDebugOp(e.target.value)}>
                {DEBUG_OPS.map((op) => <option key={op}>{op}</option>)}
              </select>
            </label>
            <button disabled={busy !== null} onClick={() => void requestDebug()} className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-50">Request session</button>
          </div>
          <div className="mt-3 space-y-1">
            {detail.debugSessions.map((s) => (
              <div key={s.id} className="flex items-center justify-between rounded bg-slate-900 px-3 py-1.5 text-sm">
                <span className="text-slate-200">{s.id.slice(0, 8)}… · {s.networkPolicy} · {s.timeoutSeconds}s cap</span>
                <Badge>{s.status}</Badge>
              </div>
            ))}
            {detail.debugSessions.length === 0 && <p className="text-xs text-slate-500">No sessions. PRODUCTION artifacts are blocked by policy; LAB sessions need a separate approver and run only on a provisioned lab worker — otherwise they honestly report NOT_PROVISIONED.</p>}
          </div>
        </Card>
      </div>
    </div>
  );
}
