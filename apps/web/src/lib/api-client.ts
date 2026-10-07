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
};
