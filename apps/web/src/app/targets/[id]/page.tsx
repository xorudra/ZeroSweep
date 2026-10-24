"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

/**
 * Target detail + ownership verification (road step 2). Until now the
 * verification API existed with no screen at all, so a target added
 * from the Targets page could never become Verified and no scan could
 * ever run. This page drives the real endpoints: start a challenge,
 * show the exact instructions the API returns, and check it — the API
 * performs a real DNS lookup / file fetch, or the second-person manual
 * approval control. Nothing here marks anything verified by itself.
 */
interface TargetRow {
  id: string;
  name: string;
  type: string;
  value: string;
  status: string;
  verified: boolean;
  description?: string | null;
  createdAt: string;
}
interface VerificationRow {
  id: string;
  method: string;
  challenge: string;
  status: string;
  expiresAt?: string | null;
  verifiedAt?: string | null;
  createdAt: string;
}

const METHODS: { value: string; label: string; hint: string }[] = [
  { value: "DNS_TXT", label: "DNS record (recommended)", hint: "You add one text record where your domain is registered. Best for domains and websites. Usually takes a few minutes to become visible." },
  { value: "HTTP_FILE", label: "File on the website", hint: "You put one small text file on the site's server. Choose this if you run the server yourself." },
  { value: "MANUAL_APPROVAL", label: "Approve it yourself", hint: "You confirm ownership on your own word and it verifies when you check. Fastest — but it's your attestation; the DNS and file methods are stronger evidence." },
];

/** Guidelines shown before the "I have permission" declaration tick.
 *  Plain words, no legalese: what you may declare, what you must not,
 *  the legal note, and what happens on a false declaration. The server
 *  records the declaration (with the network address it came from) on
 *  the verification row, visible only to platform administrators. */
const DECLARATION_GUIDELINES = [
  { title: "You may declare only if", body: "You own this target, or the owner gave you written permission to test it, or it is listed in scope of a public bug-bounty program that allows the testing you plan." },
  { title: "You must NOT declare for", body: "Any site you do not own and have no permission for — including famous sites, your college or company site, or a client's site without their say-so." },
  { title: "The legal note", body: "Testing a system without permission can be illegal — in India under the IT Act, in the US under the CFAA, and under similar laws elsewhere. You are responsible for your scans, not DSRclone." },
  { title: "If you declare falsely", body: "Your declaration is recorded with your account, the time, and the network address it came from. Your account can be blocked, your scans stopped, and the record shown to the target owner if they complain." },
];

const inputCls = "w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 outline-none focus:border-slate-500";
const btnCls = "rounded-lg bg-white px-4 py-2 text-sm font-semibold text-[#0F0F0F] transition-colors hover:bg-slate-200 disabled:opacity-50";
const ghostBtnCls = "rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-medium text-slate-200 transition-colors hover:bg-slate-800 disabled:opacity-50";

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [target, setTarget] = useState<TargetRow | null>(null);
  const [attempts, setAttempts] = useState<VerificationRow[]>([]);
  const [loadError, setLoadError] = useState("");
  const [method, setMethod] = useState(METHODS[0].value);
  const [guidelinesRead, setGuidelinesRead] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [instructions, setInstructions] = useState("");

  const load = useCallback(async () => {
    try {
      const [t, v] = await Promise.all([
        apiFetch<TargetRow>(`/targets/${id}`),
        apiFetch<VerificationRow[]>(`/targets/${id}/verifications`),
      ]);
      setTarget(t);
      setAttempts(Array.isArray(v) ? v : []);
    } catch (e) {
      setLoadError(e instanceof ApiError ? e.message : "Could not load this target.");
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  async function start() {
    setBusy(true); setError(""); setMessage("");
    try {
      const res = await apiFetch<{ instructions: string }>(`/targets/${id}/verifications`, {
        method: "POST",
        body: JSON.stringify({ method }),
      });
      setInstructions(res.instructions);
      setMessage("Challenge started — follow the instruction below, then press Check now on it.");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not start verification.");
    } finally {
      setBusy(false);
    }
  }

  async function check(verificationId: string, verificationMethod?: string) {
    setBusy(true); setError(""); setMessage("");
    if (verificationMethod === "MANUAL_APPROVAL" && !guidelinesRead) {
      setError("Read the guidelines above and tick \"I have permission\" before checking.");
      setBusy(false);
      return;
    }
    try {
      const res = await apiFetch<{ status: string; detail?: string }>(`/targets/${id}/verifications/${verificationId}/check`, {
        method: "POST",
        body: JSON.stringify(verificationMethod === "MANUAL_APPROVAL" ? { declarationAccepted: true } : {}),
      });
      if (res.status === "VERIFIED") {
        setMessage("Verified — this target is yours. You can now create an assessment for it.");
        setInstructions("");
      } else if (res.status === "EXPIRED") {
        setMessage("That challenge has expired — start a fresh one.");
      } else {
        setMessage("Not found yet. DNS changes can take a few minutes — wait a little and check again.");
      }
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not check the challenge.");
    } finally {
      setBusy(false);
    }
  }

  if (loadError) {
    return (
      <>
        <PageHeader eyebrow="Targets" title="Target" body="" />
        <EmptyState title="Could not load this target" body={loadError} />
      </>
    );
  }
  if (!target) {
    return (
      <>
        <PageHeader eyebrow="Targets" title="Target" body="" />
        <p className="text-sm text-slate-400">Loading…</p>
      </>
    );
  }

  const selected = METHODS.find((m) => m.value === method) ?? METHODS[0];
  // Guidelines must also show for a pending MANUAL_APPROVAL attempt
  // started earlier (method selector defaults to DNS_TXT on reload),
  // otherwise its Check now button could never be enabled.
  const showGuidelines = method === "MANUAL_APPROVAL" || attempts.some((a) => a.method === "MANUAL_APPROVAL" && a.status === "PENDING");

  return (
    <>
      <PageHeader
        eyebrow="Targets — step 2"
        title={target.name}
        body="One target, its details, and the proof that it's yours. A target must be verified before an assessment can scan it."
      />
      <div className="mb-6">
        <Card eyebrow="Target" title={target.value}>
          <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <div><dt className="text-xs uppercase tracking-wider text-slate-500">Type</dt><dd className="mt-1 text-slate-200">{target.type}</dd></div>
            <div><dt className="text-xs uppercase tracking-wider text-slate-500">Status</dt><dd className="mt-1 text-slate-200">{target.status}</dd></div>
            <div><dt className="text-xs uppercase tracking-wider text-slate-500">Ownership</dt><dd className="mt-1">{target.verified ? <Badge tone="VERIFIED">Verified</Badge> : <Badge tone="PENDING">Pending</Badge>}</dd></div>
            <div><dt className="text-xs uppercase tracking-wider text-slate-500">Added</dt><dd className="mt-1 text-slate-200">{new Date(target.createdAt).toLocaleString()}</dd></div>
          </dl>
          <p className="mt-4 text-sm">
            <Link href="/targets" className="text-sky-300 hover:underline">← Back to all targets</Link>
          </p>
        </Card>
      </div>

      {target.verified ? (
        <Card eyebrow="Step 2 — done" title="This target is verified">
          <p className="text-sm text-slate-300">Ownership is proven, so this target can be scanned. Next step of the road: create an assessment for it and approve the plan.</p>
          <p className="mt-4">
            <Link href="/assessments" className={btnCls + " inline-block"}>Go to assessments</Link>
          </p>
        </Card>
      ) : (
        <Card eyebrow="Step 2" title="Verify it's yours">
          <p className="text-sm text-slate-300">Pick how to prove you own this target. DSRclone really checks — nothing is marked verified until the proof is found.</p>
          {showGuidelines ? (
            <div className="mt-4 rounded-lg border border-slate-700 bg-slate-900 p-4">
              <p className="text-sm font-semibold text-slate-100">Before you declare — read this</p>
              <ul className="mt-3 space-y-3">
                {DECLARATION_GUIDELINES.map((g) => (
                  <li key={g.title} className="text-sm text-slate-300">
                    <span className="font-medium text-slate-100">{g.title}: </span>{g.body}
                  </li>
                ))}
              </ul>
              <label className="mt-4 flex cursor-pointer items-start gap-2 text-sm text-slate-200">
                <input
                  type="checkbox"
                  className="mt-0.5 h-4 w-4 accent-white"
                  checked={guidelinesRead}
                  onChange={(e) => setGuidelinesRead(e.target.checked)}
                />
                <span>I have read the guidelines and I confirm I own this target or have the owner&apos;s permission to test it.</span>
              </label>
            </div>
          ) : null}
          <div className="mt-4 grid gap-4 md:grid-cols-[260px_1fr_auto] md:items-end">
            <div>
              <label className="block text-xs font-medium uppercase tracking-wider text-slate-400" htmlFor="verify-method">Method</label>
              <select id="verify-method" className={inputCls} value={method} onChange={(e) => { setMethod(e.target.value); setGuidelinesRead(false); }}>
                {METHODS.map((m) => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>
            <p className="text-xs text-slate-500">{selected.hint}</p>
            <button type="button" onClick={() => void start()} disabled={busy || (method === "MANUAL_APPROVAL" && !guidelinesRead)} className={btnCls}>
              {busy ? "Working…" : "Start verification"}
            </button>
          </div>
          {instructions ? (
            <div className="mt-4 rounded-lg border border-slate-700 bg-slate-900 p-3">
              <p className="text-xs font-medium uppercase tracking-wider text-slate-400">Do this, then check below</p>
              <p className="mt-1 break-all font-mono text-sm text-slate-100">{instructions}</p>
            </div>
          ) : null}
          {error ? <p role="alert" className="mt-3 text-sm text-red-300">{error}</p> : null}
          {message ? <p role="status" className="mt-3 text-sm text-emerald-300">{message}</p> : null}

          {attempts.length > 0 ? (
            <div className="mt-6">
              <h3 className="text-sm font-semibold text-slate-200">Your verification attempts</h3>
              <ul className="mt-3 space-y-3">
                {attempts.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-800 px-3 py-2">
                    <span className="text-sm text-slate-200">{a.method}</span>
                    {a.status === "VERIFIED" ? <Badge tone="VERIFIED">Verified</Badge> : a.status === "EXPIRED" ? <Badge tone="PENDING">Expired</Badge> : <Badge tone="PENDING">Pending</Badge>}
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-500" title={a.challenge}>{a.challenge}</span>
                    {a.status === "PENDING" ? (
                      <button type="button" onClick={() => void check(a.id, a.method)} disabled={busy} className={ghostBtnCls}>Check now</button>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </Card>
      )}
    </>
  );
}
