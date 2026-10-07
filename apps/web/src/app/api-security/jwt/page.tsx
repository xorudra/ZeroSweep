"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * JWT profiles (Prompt 9 §58): inspection metadata for tokens observed
 * during authorized assessments — fingerprint, algorithm, issuer,
 * expiry and a REDACTED claims summary. The raw token is never stored,
 * never displayed, and signature secrets are never attacked (§24):
 * inspection is decode-and-observe only.
 */
interface JwtRow {
  id: string; fingerprint: string; algorithm: string; tokenType?: string | null;
  keyId?: string | null; issuer?: string | null; audience: string[];
  expiresAt?: string | null; lifetimeSeconds?: number | null;
  claimsSummary: Record<string, string>; source: string; host?: string | null;
  endpoint?: string | null; createdAt: string;
}

function lifetimeLabel(seconds?: number | null): string {
  if (seconds == null) return "—";
  if (seconds < 3600) return `${seconds}s`;
  if (seconds < 86400) return `${Math.round(seconds / 360) / 10}h`;
  return `${Math.round(seconds / 8640) / 10}d`;
}

export default function Page() {
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: JwtRow[] }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    apiFetch<JwtRow[]>("/api-security/jwt-profiles")
      .then((items) => { if (!cancelled) setState({ kind: "ready", items: items ?? [] }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, []);

  return (
    <>
      <PageHeader
        eyebrow="API Security · JWT"
        title="JWT Profiles"
        body="Tokens inspected during authorized assessments. Only fingerprints and redacted claim summaries are kept — sensitive claim values are replaced with type summaries before anything is stored."
      />
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Nothing to show yet" body={`${state.message} JWT profiles appear when an API assessment inspects tokens from registered auth contexts.`} />}
      {state.kind === "ready" && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="Profiles" value={state.items.length} />
            <StatCard label="Unsigned / none algorithm" value={state.items.filter((p) => p.algorithm.toLowerCase() === "none").length} />
            <StatCard label="Without expiry" value={state.items.filter((p) => !p.expiresAt).length} />
            <StatCard label="Long-lived (>24h)" value={state.items.filter((p) => (p.lifetimeSeconds ?? 0) > 86400).length} />
          </div>
          <Card title="Profiles">
            <div className="space-y-2">
              {state.items.map((p) => (
                <div key={p.id} className="text-sm text-slate-200">
                  <p className="break-all">
                    <span className="font-mono text-slate-400">{p.fingerprint.slice(0, 16)}…</span>{" "}
                    <Badge>{p.algorithm}</Badge>{" "}
                    <span className="text-slate-500">
                      {p.tokenType ?? "JWT"}{p.keyId ? ` · kid ${p.keyId}` : ""} · issuer {p.issuer ?? "—"} · lifetime {lifetimeLabel(p.lifetimeSeconds)}
                      {p.expiresAt ? ` · expires ${new Date(p.expiresAt).toLocaleDateString()}` : " · no expiry"}
                      {p.host ? ` · ${p.host}` : ""} · via {p.source}
                    </span>
                  </p>
                  <p className="break-all text-slate-500">
                    claims: {Object.entries(p.claimsSummary).map(([k, v]) => `${k}=${v}`).join(", ") || "—"}
                  </p>
                </div>
              ))}
              {state.items.length === 0 && <p className="text-sm text-slate-500">No JWT profiles recorded yet.</p>}
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
