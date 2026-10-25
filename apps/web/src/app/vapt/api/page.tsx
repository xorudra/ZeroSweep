"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@zerosweep/ui";

/**
 * API VAPT V2 workspace (Prompt 32 §153): API services, governed
 * specification import (OpenAPI/Postman/Insomnia) with host
 * validation, authorization test matrices and business-logic
 * scenarios. Specifications are UNTRUSTED documents — referenced
 * hosts are validated, embedded scripts are never executed (§35/§141).
 */
interface ApiServiceRow { id: string; baseUrl: string; host: string; apiType: string; scopeStatus: string }
interface ImportResult {
  specificationId: string; acceptedHosts: string[]; rejectedHosts: string[];
  snapshot: { hash: string; endpointCount: number; schemaCount: number };
  note: string;
}
interface MatrixResult {
  summary: { total: number; matches: number; mismatches: number; untested: number };
  entries: Array<{ id: string; resource: string; role: string; result: string }>;
}

export default function Page() {
  const [services, setServices] = useState<ApiServiceRow[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [importForm, setImportForm] = useState({ serviceId: "", format: "OPENAPI", document: "" });
  const [imported, setImported] = useState<ImportResult | null>(null);
  const [matrix, setMatrix] = useState({ testCaseId: "", rows: "" });
  const [matrixResult, setMatrixResult] = useState<MatrixResult | null>(null);
  const [scenario, setScenario] = useState({ name: "", preconditions: "", identities: "", steps: "", expectedBehavior: "" });

  const load = useCallback(async () => {
    try {
      setServices(await apiFetch<ApiServiceRow[]>("/vapt/api/services"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const doImport = async () => {
    setBusy(true);
    try {
      const result = await apiFetch<ImportResult>("/vapt/api/specifications", { method: "POST", body: JSON.stringify(importForm) });
      setImported(result);
      setNotice("Specification imported and snapshotted. The raw document is not retained — checksum + reference only.");
    } catch (e) { setError(e instanceof ApiError ? e.message : "Import failed."); } finally { setBusy(false); }
  };

  const runMatrix = async () => {
    setBusy(true);
    try {
      let rows: unknown;
      try { rows = JSON.parse(matrix.rows); } catch { setError("Matrix rows must be a JSON array."); setBusy(false); return; }
      const result = await apiFetch<MatrixResult>(`/vapt/authorization/test-cases/${matrix.testCaseId}/matrix`, { method: "POST", body: JSON.stringify({ rows }) });
      setMatrixResult(result);
    } catch (e) { setError(e instanceof ApiError ? e.message : "Matrix evaluation failed."); } finally { setBusy(false); }
  };

  const createScenario = async () => {
    setBusy(true);
    try {
      await apiFetch("/vapt/authorization/scenarios", {
        method: "POST",
        body: JSON.stringify({
          name: scenario.name, preconditions: scenario.preconditions,
          authorizedIdentities: scenario.identities.split(",").map((s) => s.trim()).filter(Boolean),
          safeSteps: scenario.steps.split("\n").map((s) => s.trim()).filter(Boolean),
          expectedBehavior: scenario.expectedBehavior,
        }),
      });
      setNotice("Business-logic scenario saved as a governed design record.");
    } catch (e) { setError(e instanceof ApiError ? e.message : "Scenario rejected."); } finally { setBusy(false); }
  };

  return (
    <main>
      <PageHeader eyebrow="Web & API VAPT V2" title="API Security Testing" />
      <p style={{ color: "var(--muted, #666)", maxWidth: 780 }}>
        API testing under the platform&apos;s operation policy: schema conformance in SAFE classes,
        state-changing operations only with explicit profile enablement, GraphQL bounded by depth and
        complexity, and authorization matrices over fixture identities — mismatches become candidate
        findings for review, never automatic confirmations.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {notice ? <p>{notice}</p> : null}

      <Card title="API services">
        {services.length === 0 ? <EmptyState title="No API services in this workspace." body="Services are created by the governed Prompt 9 import and discovery flows." /> : (
          <ul>
            {services.map((s) => <li key={s.id}><strong>{s.host}</strong> — {s.baseUrl} · {s.apiType} · {s.scopeStatus}</li>)}
          </ul>
        )}
      </Card>

      <Card title="Import specification (governed)">
        <div style={{ display: "grid", gap: 8, maxWidth: 640 }}>
          <label>API service ID <input value={importForm.serviceId} onChange={(e) => setImportForm({ ...importForm, serviceId: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Format
            <select value={importForm.format} onChange={(e) => setImportForm({ ...importForm, format: e.target.value })}>
              {["OPENAPI", "POSTMAN", "INSOMNIA", "GRAPHQL_SDL", "WSDL"].map((f) => <option key={f} value={f}>{f}</option>)}
            </select>
          </label>
          <label>Specification JSON
            <textarea value={importForm.document} rows={8} onChange={(e) => setImportForm({ ...importForm, document: e.target.value })} style={{ width: "100%" }} placeholder='{"openapi":"3.0.0","info":{"version":"1.0.0"},"servers":[{"url":"https://staging.example.com/v1"}],"paths":{}}' />
          </label>
          <button disabled={busy} onClick={() => void doImport()}>Import + snapshot</button>
          {imported ? (
            <p>Snapshot {imported.snapshot.hash.slice(0, 12)}… · endpoints {imported.snapshot.endpointCount} · schemas {imported.snapshot.schemaCount}<br />
              Accepted hosts: {imported.acceptedHosts.join(", ") || "—"} · Rejected hosts: {imported.rejectedHosts.join(", ") || "—"}<br />{imported.note}</p>
          ) : null}
        </div>
      </Card>

      <Card title="Authorization test matrix (§97–§100)">
        <div style={{ display: "grid", gap: 8, maxWidth: 640 }}>
          <label>Authorization test case ID (Prompt 9 design record)
            <input value={matrix.testCaseId} onChange={(e) => setMatrix({ ...matrix, testCaseId: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Rows (JSON array — fixture identities + resources only)
            <textarea value={matrix.rows} rows={6} onChange={(e) => setMatrix({ ...matrix, rows: e.target.value })} style={{ width: "100%" }}
              placeholder='[{"identityA":"fixture:user-a","identityB":"fixture:user-b","role":"USER","resource":"fixture:invoice/{id}","expectedAccess":"DENY","observedAccess":"ALLOW"}]' />
          </label>
          <button disabled={busy} onClick={() => void runMatrix()}>Evaluate matrix</button>
          {matrixResult ? (
            <p>{matrixResult.summary.total} rows · {matrixResult.summary.matches} match · {matrixResult.summary.mismatches} mismatch (candidate findings) · {matrixResult.summary.untested} not tested</p>
          ) : null}
        </div>
      </Card>

      <Card title="Business-logic scenario (§101/§102)">
        <div style={{ display: "grid", gap: 8, maxWidth: 640 }}>
          <label>Name <input value={scenario.name} onChange={(e) => setScenario({ ...scenario, name: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Preconditions <input value={scenario.preconditions} onChange={(e) => setScenario({ ...scenario, preconditions: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Authorized identities (comma-separated fixture references)
            <input value={scenario.identities} onChange={(e) => setScenario({ ...scenario, identities: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Safe steps (one per line — destructive steps are rejected)
            <textarea value={scenario.steps} rows={4} onChange={(e) => setScenario({ ...scenario, steps: e.target.value })} style={{ width: "100%" }} /></label>
          <label>Expected behavior <input value={scenario.expectedBehavior} onChange={(e) => setScenario({ ...scenario, expectedBehavior: e.target.value })} style={{ width: "100%" }} /></label>
          <button disabled={busy} onClick={() => void createScenario()}>Save scenario</button>
        </div>
      </Card>
    </main>
  );
}
