"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Card } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

/**
 * Create + approve assessments (road step 2, second half). Until now
 * POST /assessments and POST /assessments/:id/approve existed with no
 * screen at all — the page could only list, so an assessment could
 * never be created or approved from the UI and scans were unreachable.
 * Only VERIFIED targets are offered: scanning anything else is refused
 * by design, so the form does not pretend otherwise.
 */
interface TargetOption { id: string; name: string; value: string; verified: boolean }
interface AssessmentRow { id: string; name: string; profile: string; status: string }

const PROFILES: { value: string; label: string }[] = [
  { value: "PASSIVE_RECON", label: "Passive recon — gentlest, only looks at public traces" },
  { value: "WEB_BASELINE", label: "Web baseline — standard website checks" },
  { value: "WEB_COMPREHENSIVE", label: "Web comprehensive — deeper website checks" },
  { value: "API_ASSESSMENT", label: "API assessment" },
  { value: "NETWORK_ASSESSMENT", label: "Network assessment" },
  { value: "SOURCE_CODE", label: "Source code review" },
  { value: "CONTAINER", label: "Container image check" },
  { value: "CLOUD", label: "Cloud account check" },
  { value: "MOBILE", label: "Mobile app check" },
  { value: "CUSTOM", label: "Custom" },
];

const inputCls = "w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 outline-none focus:border-slate-500";
const labelCls = "block text-xs font-medium text-slate-400";
const btnCls = "inline-flex h-9 items-center rounded-full bg-white px-4 text-sm font-medium text-black transition-colors hover:bg-slate-200 disabled:opacity-50";

export function CreateAssessment({ onChanged }: { onChanged: () => void }) {
  const [targets, setTargets] = useState<TargetOption[] | null>(null);
  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState("");
  const [profile, setProfile] = useState(PROFILES[1].value);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  useEffect(() => {
    let cancelled = false;
    apiFetch<{ items?: TargetOption[] }>("/targets?pageSize=100")
      .then((d) => {
        if (cancelled) return;
        const verified = (d.items ?? []).filter((t) => t.verified);
        setTargets(verified);
        if (verified.length > 0) setTargetId(verified[0].id);
      })
      .catch(() => { if (!cancelled) setTargets([]); });
    return () => { cancelled = true; };
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(""); setDone("");
    try {
      // No explicit Content-Type — apiFetch sets it (see targets page note).
      await apiFetch("/assessments", {
        method: "POST",
        body: JSON.stringify({ name: name.trim(), targetId, profile }),
      });
      setDone(`"${name.trim()}" created. It starts as Pending approval — approve it in the list below, then you can preview the plan and start the scan.`);
      setName("");
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not create the assessment.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mb-6">
      <Card eyebrow="Step 2" title="Create an assessment">
        {targets === null ? (
          <p className="text-sm text-slate-400">Loading your verified targets…</p>
        ) : targets.length === 0 ? (
          <p className="text-sm text-slate-300">
            No verified target yet, so there is nothing an assessment can scan.{" "}
            <Link href="/targets" className="text-sky-300 hover:underline">Add a target and verify it first</Link>{" "}
            — that is steps 1 and 2 of the road.
          </p>
        ) : (
          <form onSubmit={submit} className="grid gap-4 md:grid-cols-[1fr_1fr_1fr_auto] md:items-end">
            <div>
              <label className={labelCls} htmlFor="assessment-name">Name</label>
              <input id="assessment-name" className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="October check of my site" required maxLength={200} />
            </div>
            <div>
              <label className={labelCls} htmlFor="assessment-target">Verified target</label>
              <select id="assessment-target" className={inputCls} value={targetId} onChange={(e) => setTargetId(e.target.value)}>
                {targets.map((t) => <option key={t.id} value={t.id}>{t.name} — {t.value}</option>)}
              </select>
            </div>
            <div>
              <label className={labelCls} htmlFor="assessment-profile">Kind of check</label>
              <select id="assessment-profile" className={inputCls} value={profile} onChange={(e) => setProfile(e.target.value)}>
                {PROFILES.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
              </select>
            </div>
            <button type="submit" disabled={busy} className={btnCls}>{busy ? "Creating…" : "Create assessment"}</button>
          </form>
        )}
        {error ? <p role="alert" className="mt-3 text-sm text-red-300">{error}</p> : null}
        {done ? <p role="status" className="mt-3 text-sm text-emerald-300">{done}</p> : null}
      </Card>
    </div>
  );
}

export function PendingApprovals({ refreshKey, onChanged }: { refreshKey: number; onChanged: () => void }) {
  const [rows, setRows] = useState<AssessmentRow[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    apiFetch<{ items?: AssessmentRow[] }>("/assessments")
      .then((d) => { if (!cancelled) setRows((d.items ?? []).filter((a) => a.status === "PENDING_APPROVAL")); })
      .catch(() => { if (!cancelled) setRows([]); });
    return () => { cancelled = true; };
  }, [refreshKey]);

  async function approve(a: AssessmentRow) {
    setBusyId(a.id); setError("");
    try {
      await apiFetch(`/assessments/${a.id}/approve`, { method: "POST", body: "{}" });
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not approve.");
    } finally {
      setBusyId(null);
    }
  }

  if (rows.length === 0) return null;
  return (
    <div className="mb-6">
      <Card eyebrow="Waiting for you" title="Approve an assessment">
        <p className="text-sm text-slate-400">Approving means: this check is allowed to run on that target. Nothing scans before this.</p>
        <ul className="mt-3 space-y-2">
          {rows.map((a) => (
            <li key={a.id} className="flex flex-wrap items-center gap-3">
              <span className="text-sm text-slate-200">{a.name}</span>
              <span className="text-xs text-slate-500">{a.profile}</span>
              <button type="button" disabled={busyId !== null} onClick={() => void approve(a)} className="rounded-full bg-white px-3.5 py-1.5 text-xs font-medium text-black transition-colors hover:bg-slate-200 disabled:opacity-50">
                {busyId === a.id ? "Approving…" : "Approve"}
              </button>
            </li>
          ))}
        </ul>
        {error ? <p role="alert" className="mt-3 text-sm text-red-300">{error}</p> : null}
      </Card>
    </div>
  );
}
