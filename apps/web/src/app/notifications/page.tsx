"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Notifications (Prompt 22 §85). The in-app inbox plus routing
 * policies. Delivery is honest: external providers (email, Slack,
 * Teams, webhooks) are configured by an administrator with
 * credential REFERENCES; until then their records read
 * RECORDED_NOT_DELIVERED / NOT_CONFIGURED — never a fake "sent".
 * Webhook destinations are SSRF-validated before a policy can save.
 */
interface NotificationRow {
  id: string; eventType: string; channel: string; status: string;
  providerStatus?: string | null; title: string; detail?: string | null;
  groupKey?: string | null; escalated: boolean; createdAt: string;
}
interface PolicyRow {
  id: string; name: string; eventTypes: string[]; channels: string[];
  dedupWindowMinutes: number; enabled: boolean; webhookUrl?: string | null;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const asArray = <T,>(x: T[] | { items: T[] }): T[] => (Array.isArray(x) ? x : x.items ?? []);

export default function Page() {
  const [notifications, setNotifications] = useState<NotificationRow[]>([]);
  const [policies, setPolicies] = useState<PolicyRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [eventType, setEventType] = useState("FINDING_CREATED");
  const [channel, setChannel] = useState("IN_APP");
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookHost, setWebhookHost] = useState("");

  const load = useCallback(async () => {
    try {
      const [n, p] = await Promise.all([
        apiFetch<NotificationRow[] | { items: NotificationRow[] }>("/notifications"),
        apiFetch<PolicyRow[] | { items: PolicyRow[] }>("/notifications/policies"),
      ]);
      setNotifications(asArray(n));
      setPolicies(asArray(p));
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load notifications");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    setBusy(true);
    try {
      await apiFetch("/notifications/policies", {
        method: "POST",
        body: JSON.stringify({
          name, eventTypes: [eventType], channels: [channel], recipients: [],
          ...(channel === "WEBHOOK" && webhookUrl
            ? { webhook: { url: webhookUrl, allowlist: webhookHost ? [webhookHost] : [], signingSecretRef: "vault:webhook-signing" } }
            : {}),
        }),
      });
      setNotice("Policy created. Webhook destinations were SSRF-validated before saving.");
      setName("");
      await load();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "create failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Continuous Security" title="Notifications" body="Provider-neutral routing with dedup, grouping, throttling, quiet hours and escalation." />
      {notice ? <p className="text-sm text-amber-300">{notice}</p> : null}
      <Card>
        <h3 className="mb-3 font-medium text-slate-100">New routing policy</h3>
        <div className="flex flex-wrap gap-2">
          <input className={inputCls} placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <select className={inputCls} value={eventType} onChange={(e) => setEventType(e.target.value)}>
            <option value="FINDING_CREATED">FINDING_CREATED</option>
            <option value="FINDING_VERIFIED">FINDING_VERIFIED</option>
            <option value="KEV_DETECTED">KEV_DETECTED</option>
            <option value="SLA_OVERDUE">SLA_OVERDUE</option>
            <option value="NEW_PUBLIC_ASSET">NEW_PUBLIC_ASSET</option>
            <option value="SCHEDULE_RUN_BLOCKED">SCHEDULE_RUN_BLOCKED</option>
          </select>
          <select className={inputCls} value={channel} onChange={(e) => setChannel(e.target.value)}>
            <option value="IN_APP">In-app</option>
            <option value="EMAIL">Email</option>
            <option value="SLACK">Slack</option>
            <option value="TEAMS">Teams</option>
            <option value="WEBHOOK">Webhook</option>
          </select>
          {channel === "WEBHOOK" ? (
            <>
              <input className={inputCls} placeholder="https://hooks.example.com/notify" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} />
              <input className={inputCls} placeholder="Allowlisted host" value={webhookHost} onChange={(e) => setWebhookHost(e.target.value)} />
            </>
          ) : null}
          <button disabled={busy || !name} onClick={() => void create()} className="rounded bg-emerald-700 px-3 py-1.5 text-sm text-white disabled:opacity-50">Create policy</button>
        </div>
        <p className="mt-2 text-xs text-slate-500">Loopback, link-local (cloud metadata), private and non-allowlisted webhook destinations are refused. Signing secrets are stored as references only.</p>
      </Card>
      {state === "loading" ? <p className="text-slate-400">Loading…</p> : null}
      {state === "error" ? <EmptyState title="Could not load" body={error} /> : null}
      {state === "ready" ? (
        <>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Policies</h3>
            {policies.length === 0 ? <EmptyState title="No policies" body="Events are not routed until a policy exists." /> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {policies.map((p) => (
                  <li key={p.id} className="flex flex-wrap items-center gap-2">
                    <span className="text-slate-100">{p.name}</span>
                    <Badge>{p.channels.join(", ")}</Badge>
                    <span className="text-slate-500">{p.eventTypes.join(", ")} · dedup {p.dedupWindowMinutes}m · {p.enabled ? "enabled" : "disabled"}</span>
                    {p.webhookUrl ? <span className="text-slate-500">{p.webhookUrl}</span> : null}
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Inbox & delivery records</h3>
            {notifications.length === 0 ? <EmptyState title="No notifications" body="Routed events, suppressions and delivery records will appear here." /> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {notifications.slice(0, 100).map((n) => (
                  <li key={n.id} className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-1">
                    <Badge>{n.channel}</Badge>
                    <Badge>{n.status}</Badge>
                    {n.providerStatus ? <span className="text-xs text-slate-500">{n.providerStatus}</span> : null}
                    <span className="text-slate-100">{n.title}</span>
                    <span className="text-slate-400">{n.detail ?? ""}</span>
                    {n.escalated ? <Badge>ESCALATED</Badge> : null}
                    <span className="text-slate-500">{new Date(n.createdAt).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      ) : null}
    </div>
  );
}
