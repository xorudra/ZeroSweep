"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
function Button({ children, onClick, variant, disabled }: { children: React.ReactNode; onClick?: () => void; variant?: string; disabled?: boolean }) {
  return (
    <button onClick={onClick} disabled={disabled} className={variant === "secondary" ? "rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50" : "rounded bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"}>
      {children}
    </button>
  );
}


/**
 * Guided onboarding (Prompt 40 §65–§75): security-first sequence with
 * an explicit authorization attestation before any active testing,
 * safe default profiles and resumable progress. There is deliberately
 * no "enable everything" shortcut (§72).
 */
interface StepState { key: string; title: string; description: string; required: boolean; state: "COMPLETED" | "SKIPPED" | "PENDING"; available: boolean }
interface OnboardingState {
  status: string; currentStep: string | null; authorizationAttested: boolean;
  defaultAssessmentProfile: string;
  progress: { total: number; completed: number; percent: number };
  steps: StepState[];
}

export default function Page() {
  const [state, setState] = useState<OnboardingState | null>(null);
  const [error, setError] = useState("");
  const [attested, setAttested] = useState(false);

  const load = useCallback(async () => {
    try {
      setState(await apiFetch<OnboardingState>("/product/onboarding"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function complete(step: string) {
    setError("");
    try {
      setState(await apiFetch<OnboardingState>(`/product/onboarding/steps/${step}/complete`, {
        method: "POST",
        body: JSON.stringify(step === "SECURITY_SCOPE" ? { attested } : {}),
      }));
    } catch (e) { setError(e instanceof ApiError ? e.message : "Could not complete the step."); }
  }

  async function skip(step: string) {
    setError("");
    try {
      setState(await apiFetch<OnboardingState>(`/product/onboarding/steps/${step}/skip`, { method: "POST", body: "{}" }));
    } catch (e) { setError(e instanceof ApiError ? e.message : "This step cannot be skipped."); }
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Getting started" title="Onboarding" body="Set up your organization safely. ZeroSweep only tests targets you own or are explicitly authorized to test — the security scope step records that attestation before any active testing (§70/§168)." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {!state && !error && <EmptyState title="Loading onboarding…" body="Fetching your onboarding progress." />}
      {state && (
        <>
          <Card>
            <div className="flex items-center gap-3">
              <h2 className="text-base font-semibold">Progress</h2>
              <Badge>{state.status}</Badge>
              <span className="text-sm text-slate-400">{state.progress.completed} of {state.progress.total} steps · {state.progress.percent}%</span>
              <span className="text-sm text-slate-400">Default assessment profile: {state.defaultAssessmentProfile} (safe standard — no unsafe one-click mode, §71/§72)</span>
            </div>
            <div className="mt-2 h-2 rounded bg-slate-800">
              <div className="h-2 rounded bg-emerald-500" style={{ width: `${state.progress.percent}%` }} />
            </div>
          </Card>
          <ol className="space-y-3">
            {state.steps.map((s, i) => (
              <li key={s.key}>
                <Card>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h3 className="font-semibold">{i + 1}. {s.title} {s.state === "COMPLETED" && <Badge>Done</Badge>} {s.state === "SKIPPED" && <Badge>Skipped</Badge>} {!s.required && <Badge>Optional</Badge>}</h3>
                      <p className="mt-1 max-w-2xl text-sm text-slate-400">{s.description}</p>
                      {s.key === "SECURITY_SCOPE" && s.state === "PENDING" && (
                        <label className="mt-2 flex items-start gap-2 text-sm text-slate-300">
                          <input type="checkbox" checked={attested} onChange={(e) => setAttested(e.target.checked)} className="mt-1" />
                          <span>I attest that this organization will only assess systems it owns or is explicitly authorized to test, and I accept the acceptable-use terms.</span>
                        </label>
                      )}
                    </div>
                    {s.state === "PENDING" && (
                      <div className="flex gap-2">
                        <Button onClick={() => void complete(s.key)} disabled={!s.available || (s.key === "SECURITY_SCOPE" && !attested)}>Complete</Button>
                        {!s.required && <Button variant="secondary" onClick={() => void skip(s.key)}>Skip</Button>}
                      </div>
                    )}
                  </div>
                </Card>
              </li>
            ))}
          </ol>
        </>
      )}
    </div>
  );
}
