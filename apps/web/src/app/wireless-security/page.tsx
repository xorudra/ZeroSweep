"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Wireless Security dashboard (Prompt 19 §71). Environments,
 * posture counts, tool health and the passive-only contract at a
 * glance. ZeroSweep wireless work is PASSIVE OBSERVATION + OFFLINE
 * capture analysis ONLY: deauthentication, handshake triggering,
 * key/handshake cracking, rogue-AP creation, jamming and client
 * connection attempts are PROHIBITED AUTOMATION (§99) that does not
 * exist here. Live RF requires dedicated sensor hardware (§13);
 * sensors report their real state — nothing is fabricated.
 */
interface EnvironmentRow {
  id: string; name: string; locationLabel?: string | null; environment: string;
  criticality: string; status: string;
  counts: { accessPoints: number; sensors: number; captures: number; events: number };
}
interface ToolRow {
  slug: string; name: string; kind: string; workerType: string; riskLevel: string;
  classification: string; health: string; detail?: string | null; capabilities: string[]; note: string;
}
interface EventRow {
  id: string; environmentId: string; type: string; timestamp?: string | null;
  bssid?: string | null; confidence: string; evidenceSummary: string; source: string;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [environments, setEnvironments] = useState<EnvironmentRow[]>([]);
  const [tools, setTools] = useState<ToolRow[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [environment, setEnvironment] = useState("CORPORATE");
  const [criticality, setCriticality] = useState("MEDIUM");

  const load = useCallback(async () => {
    try {
      const [e, t, ev] = await Promise.all([
        apiFetch<{ items: EnvironmentRow[] }>("/wireless/environments"),
        apiFetch<{ items: ToolRow[] }>("/wireless/tools"),
        apiFetch<{ items: EventRow[] }>("/wireless/events"),
      ]);
      setEnvironments(e.items);
      setTools(t.items);
      setEvents(ev.items.slice(0, 10));
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load wireless security data");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    setBusy(true);
    try {
      await apiFetch("/wireless/environments", {
        method: "POST",
        body: JSON.stringify({ name, environment, criticality }),
      });
      setNotice("Environment registered. Its target starts UNVERIFIED — verify it before scanning (§94).");
      setName("");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Failed to create environment");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Wireless Security" title="Wireless Security" body="Passive wireless inventory & posture assessment — observed data only, nothing is ever transmitted." />
      <Card>
        <p className="text-sm text-slate-300">
          <strong className="text-slate-100">Passive only.</strong> ZeroSweep observes beacons, probe
          responses and uploaded captures. It never deauthenticates clients, never triggers
          handshakes, never cracks keys, never creates rogue APs and never connects to a network.
          Rogue-AP results are defensive indicators (SUSPICIOUS is <em>not</em> a confirmed evil
          twin), stations are pseudonymized, and authentication material found in captures is
          counted — never stored.
        </p>
      </Card>

      {state === "error" && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {notice && <Card><p className="text-sm text-emerald-300">{notice}</p></Card>}

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Register environment</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <input className={inputCls} placeholder="Environment name (e.g. HQ wireless)" value={name} onChange={(e) => setName(e.target.value)} />
          <select className={inputCls} value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            {["CORPORATE", "GUEST", "LAB", "OFFICE", "PUBLIC", "UNKNOWN"].map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <select className={inputCls} value={criticality} onChange={(e) => setCriticality(e.target.value)}>
            {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((k) => <option key={k} value={k}>{k}</option>)}
          </select>
          <button className="rounded bg-sky-600 px-3 py-1.5 text-sm text-white disabled:opacity-50" disabled={busy || !name} onClick={() => void create()}>
            Register
          </button>
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Environments</h2>
        {state === "ready" && environments.length === 0 && (
          <EmptyState title="No wireless environments" body="Register an environment, approve a sensor and upload captures to begin passive assessment." />
        )}
        <div className="mt-3 space-y-2">
          {environments.map((env) => (
            <div key={env.id} className="flex flex-wrap items-center gap-3 rounded border border-slate-800 px-3 py-2">
              <Link className="text-sky-300 hover:underline" href={`/wireless-security/${env.id}`}>{env.name}</Link>
              <Badge>{env.environment}</Badge>
              <Badge>{env.criticality}</Badge>
              <span className="text-xs text-slate-400">
                {env.counts.accessPoints} APs · {env.counts.sensors} sensors · {env.counts.captures} captures · {env.counts.events} events
              </span>
              <span className="ml-auto text-xs text-slate-500">{env.status}</span>
            </div>
          ))}
        </div>
        <div className="mt-3 flex gap-4 text-sm">
          <Link className="text-sky-300 hover:underline" href="/wireless-security/sensors">Sensors</Link>
          <Link className="text-sky-300 hover:underline" href="/wireless-security/events">Events &amp; drift</Link>
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Recent wireless events</h2>
        {events.length === 0 && <p className="mt-2 text-sm text-slate-400">No events recorded. Events come from passive observation only — detection never triggers a transmission.</p>}
        <div className="mt-3 space-y-2">
          {events.map((ev) => (
            <div key={ev.id} className="rounded border border-slate-800 px-3 py-2 text-sm">
              <Badge>{ev.type}</Badge>{" "}
              <span className="text-slate-300">{ev.evidenceSummary}</span>{" "}
              <span className="text-xs text-slate-500">confidence {ev.confidence} · {ev.source}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-slate-100">Tool health</h2>
        <div className="mt-3 space-y-2">
          {tools.map((t) => (
            <div key={t.slug} className="rounded border border-slate-800 px-3 py-2 text-sm">
              <span className="text-slate-100">{t.name}</span>{" "}
              <Badge>{t.kind}</Badge> <Badge>{t.classification}</Badge> <Badge>{t.health}</Badge>
              <p className="mt-1 text-xs text-slate-400">{t.detail ?? t.note}</p>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
