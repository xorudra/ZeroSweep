"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Mobile Security dashboard (Prompt 17 §93). Applications, builds,
 * findings, device lab and tool health at a glance. Static analysis
 * is the DEFAULT (§8): apps are never installed, run, emulated or
 * instrumented from this product outside an explicitly approved,
 * controlled lab session — and credential theft, token theft,
 * account takeover, payment abuse, persistence, spyware behavior,
 * data extraction, security-control bypass, arbitrary ADB shell,
 * arbitrary Frida scripts and arbitrary Objection commands are
 * PROHIBITED AUTOMATION (§75/§119) that does not exist here.
 */
interface AppRow {
  id: string; name: string; platform: string; packageName?: string | null; bundleId?: string | null;
  environment: string; criticality: string; status: string; builds: number; findings: number;
}
interface ToolRow {
  slug: string; name: string; workerType: string; risk: string;
  approvalRequirement: string; health: string; version?: string | null; capabilities: string[];
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const SUBNAV = [
  { href: "/mobile-security/devices", label: "Device Lab" },
  { href: "/mobile-security/traffic", label: "Traffic" },
] as const;

export default function Page() {
  const [apps, setApps] = useState<AppRow[]>([]);
  const [tools, setTools] = useState<ToolRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [platform, setPlatform] = useState<"ANDROID" | "IOS">("ANDROID");
  const [identity, setIdentity] = useState("");
  const [environment, setEnvironment] = useState("PRODUCTION");

  const load = useCallback(async () => {
    try {
      const [a, t] = await Promise.all([
        apiFetch<{ items: AppRow[] }>("/mobile/apps"),
        apiFetch<{ items: ToolRow[] }>("/mobile/tools"),
      ]);
      setApps(a.items);
      setTools(t.items);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load mobile security data");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const register = async () => {
    setBusy("register");
    setNotice("");
    try {
      await apiFetch("/mobile/apps", {
        method: "POST",
        body: JSON.stringify({
          name, platform, environment, criticality: "HIGH",
          ...(platform === "ANDROID" ? { packageName: identity } : { bundleId: identity }),
        }),
      });
      setNotice("Application registered. Its target starts UNVERIFIED — verify it before scanning.");
      setName(""); setIdentity("");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Registration failed");
    } finally { setBusy(null); }
  };

  const totalFindings = apps.reduce((s, a) => s + a.findings, 0);
  const totalBuilds = apps.reduce((s, a) => s + a.builds, 0);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Mobile Security" title="Mobile Security" body="Mobile application VAPT for Android & iOS — static analysis by default, a governed device lab for controlled dynamic work, and secrets that are only ever metadata." />
      <div className="flex gap-2">
        {SUBNAV.map((l) => (
          <Link key={l.href} href={l.href} className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-700">{l.label}</Link>
        ))}
      </div>
      {notice && <p className="text-sm text-amber-300">{notice}</p>}
      {state === "error" && <p className="text-sm text-red-400">{error}</p>}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <Card><p className="text-2xl font-semibold text-slate-100">{apps.length}</p><p className="text-sm text-slate-400">Applications</p></Card>
        <Card><p className="text-2xl font-semibold text-slate-100">{totalBuilds}</p><p className="text-sm text-slate-400">Builds (SHA-256 identity)</p></Card>
        <Card><p className="text-2xl font-semibold text-slate-100">{totalFindings}</p><p className="text-sm text-slate-400">Mobile findings</p></Card>
        <Card><p className="text-2xl font-semibold text-slate-100">{tools.filter((t) => t.health === "HEALTHY").length}/{tools.length}</p><p className="text-sm text-slate-400">Tools healthy (§102)</p></Card>
      </div>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Register application</h2>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-sm text-slate-400">Name
            <input className={`${inputCls} ml-2`} value={name} onChange={(e) => setName(e.target.value)} placeholder="Example App" />
          </label>
          <label className="text-sm text-slate-400">Platform
            <select className={`${inputCls} ml-2`} value={platform} onChange={(e) => setPlatform(e.target.value as "ANDROID" | "IOS")}>
              <option value="ANDROID">Android</option>
              <option value="IOS">iOS</option>
            </select>
          </label>
          <label className="text-sm text-slate-400">{platform === "ANDROID" ? "Package name" : "Bundle ID"}
            <input className={`${inputCls} ml-2`} value={identity} onChange={(e) => setIdentity(e.target.value)} placeholder={platform === "ANDROID" ? "com.example.app" : "com.example.iosapp"} />
          </label>
          <label className="text-sm text-slate-400">Environment
            <select className={`${inputCls} ml-2`} value={environment} onChange={(e) => setEnvironment(e.target.value)}>
              <option>PRODUCTION</option><option>STAGING</option><option>DEVELOPMENT</option><option>LAB</option><option>UNKNOWN</option>
            </select>
          </label>
          <button disabled={busy !== null || !name || !identity} onClick={() => void register()} className="rounded bg-indigo-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">
            {busy === "register" ? "Registering…" : "Register"}
          </button>
        </div>
        <p className="mt-2 text-xs text-slate-500">No store accounts, signing keys or credentials are ever collected — anything of that kind exists only as a secret reference.</p>
      </Card>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Applications</h2>
        {state === "ready" && apps.length === 0 && <EmptyState title="No applications registered" body="Register an application, then upload a build for static analysis." />}
        <div className="space-y-2">
          {apps.map((a) => (
            <div key={a.id} className="flex flex-wrap items-center justify-between gap-2 rounded bg-slate-900 px-3 py-2">
              <div>
                <Link href={`/mobile-security/apps/${a.id}`} className="font-medium text-indigo-300 hover:underline">{a.name}</Link>
                <p className="text-xs text-slate-400">{a.packageName ?? a.bundleId ?? "—"} · {a.environment} · {a.builds} builds · {a.findings} findings</p>
              </div>
              <div className="flex items-center gap-2">
                <Badge>{a.platform}</Badge>
                <Badge>{a.status}</Badge>
              </div>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-lg font-medium text-slate-100">Tool health (§102)</h2>
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
        <p className="mt-2 text-xs text-slate-500">Frida is DISABLED by default and Objection is APPROVAL_REQUIRED: instrumentation exists only as administrator-reviewed, versioned modules inside an approved lab session (§69–§74). No automated root/jailbreak or certificate-pinning bypass exists in any profile.</p>
      </Card>
    </div>
  );
}
