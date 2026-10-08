"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface ReviewRow { id: string; title: string; status: string; createdAt: string }
interface ItemRow { id: string; subjectType: string; subjectLabel: string; decision: string | null }
interface PrivReport { privilegedMemberships: { userId: string; role: string }[]; serviceAccounts: { id: string; name: string }[]; highScopeApiKeys: { id: string; prefix: string }[] }

/**
 * Access reviews & privileged access (Prompt 23 §94–97). Reviews snapshot
 * privileged subjects; decisions execute through the normal permission
 * services (revoke membership, disable service account, revoke key) —
 * there is no review-only shadow state.
 */
export default function AccessReviewsPage() {
  const [orgId, setOrgId] = useState("");
  const [reviews, setReviews] = useState<ReviewRow[]>([]);
  const [items, setItems] = useState<ItemRow[]>([]);
  const [openReview, setOpenReview] = useState<string | null>(null);
  const [report, setReport] = useState<PrivReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [title, setTitle] = useState("Quarterly access review");

  const load = useCallback(async () => {
    try {
      const me = await apiFetch<{ organizationId: string }>("/auth/me");
      setOrgId(me.organizationId);
      setReviews(await apiFetch<ReviewRow[]>(`/organizations/${me.organizationId}/access-reviews`));
      setReport(await apiFetch<PrivReport>(`/organizations/${me.organizationId}/privileged-report`));
    } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    setError(null);
    try { await fn(); setNotice(msg); await load(); } catch (e) { setError((e as Error).message); }
  };

  const open = async (id: string) => {
    try {
      const res = await apiFetch<{ items: ItemRow[] }>(`/organizations/${orgId}/access-reviews/${id}`);
      setItems(res.items); setOpenReview(id);
    } catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="Access reviews" body="Periodic certification of privileged access. Revocations take effect immediately and are audited." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      {report && (
        <Card>
          <h2 className="font-semibold">Privileged access right now</h2>
          <p className="mt-2 text-sm text-slate-400">{report.privilegedMemberships.length} privileged memberships · {report.serviceAccounts.length} active service accounts · {report.highScopeApiKeys.length} high-scope API keys</p>
        </Card>
      )}
      <Card>
        <h2 className="font-semibold">Reviews</h2>
        {reviews.map((r) => (
          <div key={r.id} className="mt-2 flex items-center gap-3 text-sm">
            <span className="font-medium">{r.title}</span><Badge>{r.status}</Badge>
            <button className="text-sky-300 hover:underline" onClick={() => void open(r.id)}>Open</button>
            {r.status === "OPEN" && <button className="text-emerald-300 hover:underline" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/access-reviews/${r.id}/complete`, { method: "POST" }), "Review completed.")}>Complete</button>}
          </div>
        ))}
        <div className="mt-3 flex gap-2">
          <input className="rounded bg-slate-900 px-3 py-2 text-sm" value={title} onChange={(e) => setTitle(e.target.value)} />
          <button className="rounded bg-sky-600 px-4 py-2 text-sm" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/access-reviews`, { method: "POST", body: JSON.stringify({ title }) }), "Review created with a snapshot of current privileged subjects.")}>Start review</button>
        </div>
        {openReview && items.map((i) => (
          <div key={i.id} className="mt-2 flex flex-wrap items-center gap-3 border-t border-slate-800 pt-2 text-sm">
            <Badge>{i.subjectType}</Badge><span>{i.subjectLabel}</span>
            <span className="text-slate-400">{i.decision ?? "Undecided"}</span>
            {!i.decision && ["KEEP", "REVOKE", "DISABLE"].map((d) => (
              <button key={d} className="text-sky-300 hover:underline" onClick={() => void act(async () => { await apiFetch(`/organizations/${orgId}/access-reviews/${openReview}/items/${i.id}/decide`, { method: "POST", body: JSON.stringify({ decision: d }) }); await open(openReview); }, `Decision ${d} executed.`)}>{d}</button>
            ))}
          </div>
        ))}
      </Card>
    </div>
  );
}
