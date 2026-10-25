"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Billing view (Prompt 40 §109). Shown only with billing data from a
 * configured provider. When no provider is configured the page says so
 * plainly — the platform never simulates a payment flow (§21).
 */
interface BillingView {
  status: { status: string; provider: string | null; reason: string };
  events: Array<{ id: string; type: string; status: string; createdAt: string }>;
  invoices: Array<{ id: string; externalInvoiceId: string; status: string; amountMinor: number | null; currency: string | null; issuedAt: string | null }>;
}

export default function Page() {
  const [view, setView] = useState<BillingView | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setView(await apiFetch<BillingView>("/product/billing"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Settings" title="Billing" body="Billing status, provider events and invoice references for your organization. ZeroSweep never stores card data (§26)." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {!view && !error && <EmptyState title="Loading billing…" body="Fetching billing state." />}
      {view && view.status.status === "NOT_CONFIGURED" && (
        <EmptyState
          title="Billing is not configured for this deployment"
          body="No payment provider is configured, so there is no checkout, no payment method and nothing to pay here. Subscriptions are managed by your platform operator. The platform never simulates a payment flow."
        />
      )}
      {view && view.status.status !== "NOT_CONFIGURED" && (
        <>
          <Card>
            <div className="flex items-center gap-3">
              <h2 className="text-base font-semibold">Provider</h2>
              <Badge>{view.status.provider ?? "—"}</Badge>
              <Badge>{view.status.status}</Badge>
              <span className="text-sm text-slate-400">{view.status.reason}</span>
            </div>
          </Card>
          <Card>
            <h2 className="mb-3 text-base font-semibold">Invoices</h2>
            {view.invoices.length === 0 ? <EmptyState title="No invoices" body="No invoice references recorded yet." /> : (
              <table className="w-full text-sm">
                <thead><tr className="text-left text-slate-400"><th className="py-1">Reference</th><th>Status</th><th>Amount</th><th>Issued</th></tr></thead>
                <tbody>
                  {view.invoices.map((i) => (
                    <tr key={i.id} className="border-t border-slate-800">
                      <td className="py-1">{i.externalInvoiceId}</td><td>{i.status}</td>
                      <td>{i.amountMinor === null ? "—" : `${(i.amountMinor / 100).toFixed(2)} ${i.currency ?? ""}`}</td>
                      <td>{i.issuedAt ? new Date(i.issuedAt).toLocaleDateString() : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <Card>
            <h2 className="mb-3 text-base font-semibold">Billing events</h2>
            {view.events.length === 0 ? <EmptyState title="No events" body="No billing events processed yet." /> : (
              <ul className="space-y-1 text-sm">
                {view.events.map((e) => (
                  <li key={e.id} className="flex justify-between border-t border-slate-800 py-1">
                    <span>{e.type}</span><span className="text-slate-400">{e.status} · {new Date(e.createdAt).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
