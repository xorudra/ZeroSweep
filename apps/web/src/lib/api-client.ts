/**
 * API client architecture: the web app only ever talks to the versioned API
 * (/api/v1). Auth token is kept in localStorage (foundation phase) and sent
 * as a Bearer header; every request carries an x-request-id for tracing.
 */
const BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000/api/v1";
const TOKEN_KEY = "dsrclone.accessToken";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(TOKEN_KEY);
}
export function setToken(token: string): void {
  window.localStorage.setItem(TOKEN_KEY, token);
}
export function clearToken(): void {
  window.localStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) { super(message); }
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      "x-request-id": crypto.randomUUID(),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(init.headers ?? {}),
    },
  });
  if (res.status === 401 && token && typeof window !== "undefined" && window.location.pathname !== "/login") {
    // The session expired (tokens live 1h). Clear it and return to the
    // sign-in page instead of leaving every screen failing quietly —
    // gated pages like the admin plane otherwise look "gone" until a
    // manual logout/login cycle.
    clearToken();
    window.location.assign("/login");
    throw new ApiError(401, "Session expired — please sign in again.");
  }
  if (!res.ok) {
    let message = `Request failed (${res.status})`;
    try {
      const body = (await res.json()) as { message?: string };
      if (body.message) message = Array.isArray(body.message) ? body.message.join(", ") : body.message;
    } catch { /* keep default message */ }
    throw new ApiError(res.status, message);
  }
  return (await res.json()) as T;
}

export const api = {
  health: () => apiFetch("/health"),
  me: () => apiFetch("/auth/me"),
  login: (email: string, password: string) =>
    apiFetch<{ accessToken: string }>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  register: (name: string, email: string, password: string, organizationName: string) =>
    apiFetch<{ accessToken: string }>("/auth/register", { method: "POST", body: JSON.stringify({ name, email, password, organizationName }) }),
  targets: () => apiFetch("/targets"),
  assessments: () => apiFetch("/assessments"),
  scans: () => apiFetch("/scans"),
  findings: () => apiFetch("/findings"),
  reports: () => apiFetch("/reports"),
  tools: () => apiFetch("/tools"),
  auditLogs: () => apiFetch("/audit-logs"),
  // Prompt 4 orchestration
  planPreview: (assessmentId: string) =>
    apiFetch(`/assessments/${assessmentId}/plan`, { method: "POST", body: JSON.stringify({}) }),
  startScan: (assessmentId: string) =>
    apiFetch<{ scanId: string; status: string; simulation: boolean }>(`/assessments/${assessmentId}/scans`, { method: "POST", body: JSON.stringify({}) }),
  scanDetails: (scanId: string) => apiFetch(`/scans/${scanId}/details`),
  scanEvents: (scanId: string) => apiFetch(`/scans/${scanId}/events?pageSize=100`),
  pauseScan: (scanId: string) => apiFetch(`/scans/${scanId}/pause`, { method: "POST", body: JSON.stringify({}) }),
  resumeScan: (scanId: string) => apiFetch(`/scans/${scanId}/resume`, { method: "POST", body: JSON.stringify({}) }),
  cancelScan: (scanId: string) => apiFetch(`/scans/${scanId}/cancel`, { method: "POST", body: JSON.stringify({}) }),
  stopScan: (scanId: string) => apiFetch(`/scans/${scanId}/stop`, { method: "POST", body: JSON.stringify({}) }),
  // Prompt 5 recon inventory
  assets: (query = "") => apiFetch(`/assets${query}`),
  asset: (id: string) => apiFetch(`/assets/${id}`),
  assetServices: (id: string) => apiFetch(`/assets/${id}/services`),
  assetEndpoints: (id: string) => apiFetch(`/assets/${id}/endpoints`),
  endpoints: (query = "") => apiFetch(`/endpoints${query}`),
  scanAssets: (scanId: string) => apiFetch(`/scans/${scanId}/assets`),
  scanEndpoints: (scanId: string) => apiFetch(`/scans/${scanId}/endpoints`),
  reconSummary: (scanId: string) => apiFetch(`/scans/${scanId}/recon-summary`),
  webSurface: (scanId: string) => apiFetch(`/scans/${scanId}/web-surface`),
  assetWebSurface: (id: string) => apiFetch(`/assets/${id}/web-surface`),
  endpoint: (id: string) => apiFetch(`/endpoints/${id}`),
  endpointParameters: (id: string) => apiFetch(`/endpoints/${id}/parameters`),
  toolHealth: (slug: string) => apiFetch(`/tools/${slug}/health`),
  // Prompt 7 findings + governance
  finding: (id: string) => apiFetch(`/findings/${id}`),
  findingEvidence: (id: string) => apiFetch(`/findings/${id}/evidence`),
  findingsSummary: () => apiFetch("/findings/summary"),
  reviewFinding: (id: string, status: string, notes: string) =>
    apiFetch(`/findings/${id}/review`, { method: "POST", body: JSON.stringify({ status, notes }) }),
  scanFindings: (scanId: string) => apiFetch(`/scans/${scanId}/findings`),
  scanFindingsSummary: (scanId: string) => apiFetch(`/scans/${scanId}/findings-summary`),
  templatePolicy: () => apiFetch("/tools/template-policy"),
};
