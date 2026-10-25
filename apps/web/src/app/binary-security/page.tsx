"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Binary Security dashboard (Prompt 18 §85). Registered artifacts,
 * formats, hardening posture, findings and tool health at a glance.
 * Binaries are hostile content: they are PARSED statically and are
 * NEVER executed, loaded, debugged or emulated by ZeroSweep (§8).
 * Exploit generation, shellcode, ROP chains, malware creation,
 * payload injection, credential dumping, process injection,
 * persistence, privilege escalation, sandbox escape and AV/EDR
 * evasion are PROHIBITED AUTOMATION (§78/§123) that does not exist
 * here.
 */
interface ArtifactRow {
  id: string; name: string; source: string; sha256: string; sizeBytes: string;
  format: string; architecture?: string | null; environment: string; status: string; findings: number;
}
interface ToolRow {
  slug: string; name: string; workerType: string; risk: string;
  approvalRequirement: string; health: string; detail?: string | null; capabilities: string[]; license?: string;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [artifacts, setArtifacts] = useState<ArtifactRow[]>([]);
  const [tools, setTools] = useState<ToolRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [sha256, setSha256] = useState("");
  const [sizeBytes, setSizeBytes] = useState("");
  const [source, setSource] = useState("UPLOAD");
  const [environment, setEnvironment] = useState("PRODUCTION");

  const load = useCallback(async () => {
    try {
      const [a, t] = await Promise.all([
        apiFetch<{ items: ArtifactRow[] }>("/binaries"),
        apiFetch<{ items: ToolRow[] }>("/binary/tools"),
      ]);
      setArtifacts(a.items);
      setTools(t.items);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load binary security data");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const register = async () => {
    setBusy("register");
    setNotice("");
    try {
      await apiFetch("/binaries", {
        method: "POST",
        body: JSON.stringify({
          name, source, sha256: sha256.trim().toLowerCase(),
          sizeBytes: Number(sizeBytes || 0), environment,
        }),
      });
      setNotice("Artifact registered under its SHA-256 identity. Its target starts UNVERIFIED — verify it before scanning. The artifact itself is never executed.");
      setName(""); setSha256(""); setSizeBytes("");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Registration failed");
    } finally { setBusy(null); }
  };

  const totalFindings = artifacts.reduce((s, a) => s + a.findings, 0);
  const formats = new Set(artifacts.map((a) => a.format)).size;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Binary Security" title="Binary Security" body="Reverse engineering & binary analysis for authorized artifacts — static analysis only, hardening and dependency intelligence, cross-build diffs, and a governed debug lab that never fabricates a run." />
      {notice && <p className="text-sm text-amber-300">{notice}</p>}
      {state === "error" && <p className="text-sm text-red-400">{error}</p>}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card><p className="text-2xl font-semibold text-slate-100">{artifacts.length}</p><p className="text-sm text-slate-400">Artifacts (SHA-256 identity)</p></Card>
        <Card><p className="text-2xl font-semibold text-slate-100">{formats}</p><p className="text-sm text-slate-400">Formats identified (magic bytes)</p></Card>
        <Card><p className="text-2xl font-semibold text-slate-100">{totalFindings}</p><p className="text-sm text-slate-400">Binary findings</p></Card>
        <Card><p className="text-2xl font-semibold text-slate-100">{tools.filter((t) => t.health === "HEALTHY").length}/{tools.length}</p><p className="text-sm text-slate-400">Tools healthy (§95)</p></Card>
      </div>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Register artifact</h2>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm text-slate-400">Name
            <input className={`${inputCls} ml-2`} value={name} onChange={(e) => setName(e.target.value)} placeholder="app-hardened" />
          </label>
          <label className="text-sm text-slate-400">SHA-256
            <input className={`${inputCls} ml-2 w-72`} value={sha256} onChange={(e) => setSha256(e.target.value)} placeholder="64 hex characters — the artifact identity" />
          </label>
          <label className="text-sm text-slate-400">Size (bytes)
            <input className={`${inputCls} ml-2 w-32`} value={sizeBytes} onChange={(e) => setSizeBytes(e.target.value)} placeholder="4096" />
          </label>
          <label className="text-sm text-slate-400">Source
            <select className={`${inputCls} ml-2`} value={source} onChange={(e) => setSource(e.target.value)}>
              <option>UPLOAD</option><option>MOBILE_BUILD</option><option>CONTAINER_IMAGE</option><option>SOURCE_BUILD</option><option>CONTROLLED_LAB</option>
            </select>
          </label>
          <label className="text-sm text-slate-400">Environment
            <select className={`${inputCls} ml-2`} value={environment} onChange={(e) => setEnvironment(e.target.value)}>
              <option>PRODUCTION</option><option>STAGING</option><option>DEVELOPMENT</option><option>LAB</option><option>UNKNOWN</option>
            </select>
          </label>
          <button disabled={busy !== null || !name || sha256.trim().length !== 64} onClick={() => void register()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">
            {busy === "register" ? "Registering…" : "Register"}
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500">Format is identified from magic bytes, never from the file name — a PDF-named ELF registers as ELF. Debugging is possible only for LAB artifacts, with a separate approver.</p>
      </Card>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Artifacts</h2>
        {state === "ready" && artifacts.length === 0 && <EmptyState title="No artifacts registered" body="Register a binary artifact by its SHA-256, then run a static scan profile." />}
        <div className="space-y-2">
          {artifacts.map((a) => (
            <div key={a.id} className="flex flex-wrap items-center justify-between gap-2 rounded bg-slate-900 px-3 py-2">
              <div>
                <Link href={`/binary-security/${a.id}`} className="font-medium text-indigo-300 hover:underline">{a.name}</Link>
                <p className="text-xs text-slate-400">{a.sha256.slice(0, 16)}… · {a.architecture ?? "unknown arch"} · {a.environment} · {a.findings} findings</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge>{a.format}</Badge>
                <Badge>{a.status}</Badge>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Tool health (§95/§96)</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead><tr className="text-slate-400"><th className="py-1 pr-3">Tool</th><th className="py-1 pr-3">Worker</th><th className="py-1 pr-3">Risk</th><th className="py-1 pr-3">Approval</th><th className="py-1">Health</th></tr></thead>
            <tbody>
              {tools.map((t) => (
                <tr key={t.slug} className="border-t border-slate-800">
                  <td className="py-1.5 pr-3 text-slate-200">{t.name}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{t.workerType}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{t.risk}</td>
                  <td className="py-1.5 pr-3 text-slate-400">{t.approvalRequirement}</td>
                  <td className="py-1.5"><Badge>{t.health}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-xs text-slate-500">IDA and Binary Ninja are optional commercial connectors — never bundled, licenses never bypassed; the open-source baseline works fully without them (§96). GDB is DISABLED outside the LAB and pwndbg is APPROVAL_REQUIRED: both are governed session descriptors, not pipeline tools. Cutter is an analyst-workstation tool.</p>
      </Card>
    </div>
  );
}
