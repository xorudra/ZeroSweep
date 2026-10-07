"use client";

import { useEffect, useState } from "react";
import { EmptyState } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface ListResponse { items?: unknown[]; total?: number; }

/** Shared list pattern: loading -> error -> empty -> table.
 *  Empty means empty: this foundation never renders invented rows. */
export function ResourceList({
  path, emptyTitle, emptyBody, columns, renderRow,
}: {
  path: string;
  emptyTitle: string;
  emptyBody: string;
  columns: string[];
  renderRow: (item: never, idx: number) => React.ReactNode;
}) {
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: unknown[] }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    apiFetch<ListResponse | unknown[]>(path)
      .then((data) => {
        if (cancelled) return;
        const items = Array.isArray(data) ? data : data.items ?? [];
        setState({ kind: "ready", items });
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API. Is it running on the API port?" });
      });
    return () => { cancelled = true; };
  }, [path]);

  if (state.kind === "loading") return <p className="text-sm text-slate-400">Loading…</p>;
  if (state.kind === "error") {
    return <EmptyState title="Nothing to show yet" body={`${state.message} When the API is running and data exists, it will appear here — no placeholder data is shown.`} />;
  }
  if (state.items.length === 0) return <EmptyState title={emptyTitle} body={emptyBody} />;
  return (
    <div className="overflow-x-auto rounded-xl border border-slate-800">
      <table className="w-full min-w-[560px] text-left text-sm">
        <thead className="bg-slate-900/70 text-slate-400">
          <tr>{columns.map((c) => <th key={c} className="px-4 py-3 font-medium">{c}</th>)}</tr>
        </thead>
        <tbody>
          {state.items.map((item, i) => renderRow(item as never, i))}
        </tbody>
      </table>
    </div>
  );
}

export function Row({ cells }: { cells: React.ReactNode[] }) {
  return (
    <tr className="border-t border-slate-800">
      {cells.map((c, i) => <td key={i} className="px-4 py-3 text-slate-200">{c}</td>)}
    </tr>
  );
}
