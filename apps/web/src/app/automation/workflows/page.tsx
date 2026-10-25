"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Automation workflows (Prompt 22 §84). Typed triggers, conditions
 * and actions ONLY — there is deliberately no code editor and no
 * arbitrary-action field: a workflow definition can never contain
 * executable content (§61/§62). Execution is loop-guarded (§63).
 */
interface WorkflowRow {
  id: string; name: string; trigger: string; enabled: boolean; version: number;
  conditions: Array<{ field: string; operator: string; value: unknown }>;
  actions: Array<{ type: string; params?: Record<string, string> }>;
}
interface ExecutionRow {
  id: string; workflowId: string; trigger: string; status: string; startedAt: string;
  actions: Array<{ type: string; outcome: string }>; errors: string[];
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const asArray = <T,>(x: T[] | { items: T[] }): T[] => (Array.isArray(x) ? x : x.items ?? []);
const TRIGGERS = ["FINDING_CREATED", "FINDING_VERIFIED", "FINDING_REOPENED", "KEV_DETECTED", "SLA_DUE_SOON", "SLA_OVERDUE", "NEW_PUBLIC_ASSET", "RISK_INCREASED", "SCAN_FAILED", "REPORT_READY"];
const ACTIONS = ["CREATE_NOTIFICATION", "ASSIGN_FINDING", "SET_PRIORITY", "REQUEST_SAFE_RETEST", "CREATE_REPORT_DRAFT", "CREATE_ANALYST_TASK", "ADD_TAG"];

export default function Page() {
  const [workflows, setWorkflows] = useState<WorkflowRow[]>([]);
  const [executions, setExecutions] = useState<ExecutionRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [trigger, setTrigger] = useState("FINDING_VERIFIED");
  const [condField, setCondField] = useState("severity");
  const [condValue, setCondValue] = useState("CRITICAL");
  const [actionType, setActionType] = useState("CREATE_NOTIFICATION");
  const [actionParam, setActionParam] = useState("");

  const load = useCallback(async () => {
    try {
      const [w, e] = await Promise.all([
        apiFetch<WorkflowRow[] | { items: WorkflowRow[] }>("/workflows"),
        apiFetch<ExecutionRow[] | { items: ExecutionRow[] }>("/workflows/executions"),
      ]);
      setWorkflows(asArray(w));
      setExecutions(asArray(e));
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load workflows");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    setBusy(true);
    try {
      const params: Record<string, string> = {};
      if (actionType === "SET_PRIORITY" && actionParam) params.priority = actionParam;
      if (actionType === "ASSIGN_FINDING" && actionParam) params.assigneeId = actionParam;
      if (actionType === "ADD_TAG" && actionParam) params.tag = actionParam;
      if (actionType === "CREATE_NOTIFICATION") params.channel = "IN_APP";
      await apiFetch("/workflows", {
        method: "POST",
        body: JSON.stringify({
          name, trigger,
          conditions: condValue ? [{ field: condField, operator: "eq", value: condValue }] : [],
          actions: [{ type: actionType, params }],
        }),
      });
      setNotice("Workflow created (typed definition validated — no code content possible).");
      setName("");
      await load();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "create failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Automation" title="Automation Workflows" body="Typed event → condition → action automation with loop protection. No scripts, no shell, no arbitrary HTTP — ever." />
      {notice ? <p className="text-sm text-amber-300">{notice}</p> : null}
      <Card>
        <h3 className="mb-3 font-medium text-slate-100">New workflow</h3>
        <div className="flex flex-wrap gap-2">
          <input className={inputCls} placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <select className={inputCls} value={trigger} onChange={(e) => setTrigger(e.target.value)}>
            {TRIGGERS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <select className={inputCls} value={condField} onChange={(e) => setCondField(e.target.value)}>
            <option value="severity">severity =</option>
            <option value="priority">priority =</option>
            <option value="environment">environment =</option>
            <option value="verification">verification =</option>
            <option value="domain">domain =</option>
          </select>
          <input className={inputCls} placeholder="Condition value" value={condValue} onChange={(e) => setCondValue(e.target.value)} />
          <select className={inputCls} value={actionType} onChange={(e) => setActionType(e.target.value)}>
            {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
          </select>
          {(actionType === "SET_PRIORITY" || actionType === "ASSIGN_FINDING" || actionType === "ADD_TAG") ? (
            <input className={inputCls} placeholder={actionType === "SET_PRIORITY" ? "P0..P4" : actionType === "ADD_TAG" ? "tag" : "assignee id"} value={actionParam} onChange={(e) => setActionParam(e.target.value)} />
          ) : null}
          <button disabled={busy || !name} onClick={() => void create()} className="rounded bg-emerald-700 px-3 py-1.5 text-sm text-white disabled:opacity-50">Create workflow</button>
        </div>
        <p className="mt-2 text-xs text-slate-500">REQUEST_SAFE_RETEST routes through the RetestRouter + governed SAFE validator catalog — intrusive validation can never be a workflow action.</p>
      </Card>
      {state === "loading" ? <p className="text-slate-400">Loading…</p> : null}
      {state === "error" ? <EmptyState title="Could not load" body={error} /> : null}
      {state === "ready" ? (
        <>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Workflows</h3>
            {workflows.length === 0 ? <EmptyState title="No workflows" body="Create one above to automate triage, notification and safe retests." /> : (
              <ul className="space-y-2 text-sm text-slate-300">
                {workflows.map((w) => (
                  <li key={w.id} className="border-b border-slate-800 pb-2">
                    <span className="text-slate-100">{w.name}</span> <Badge>{w.trigger}</Badge>
                    <span className="ml-2 text-slate-500">{w.enabled ? "enabled" : "disabled"} · v{w.version}</span>
                    <p className="text-xs text-slate-500">
                      when {w.conditions.map((c) => `${c.field} ${c.operator} ${String(c.value)}`).join(" AND ") || "always"} → {w.actions.map((a) => a.type).join(", ")}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Executions</h3>
            {executions.length === 0 ? <p className="text-sm text-slate-500">No executions yet.</p> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {executions.slice(0, 50).map((e) => (
                  <li key={e.id} className="flex flex-wrap items-center gap-2">
                    <Badge>{e.status}</Badge>
                    <span>{e.trigger}</span>
                    <span className="text-slate-400">{e.actions.map((a) => `${a.type}:${a.outcome}`).join(" · ")}</span>
                    <span className="text-slate-500">{new Date(e.startedAt).toLocaleString()}</span>
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
