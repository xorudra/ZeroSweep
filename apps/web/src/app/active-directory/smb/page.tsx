"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * SMB posture (Prompt 15 §97): share INVENTORY and permission
 * metadata only. Share contents are never browsed, read or
 * downloaded (§44) — there is deliberately no content view.
 */
interface SmbData {
  items: Array<{ id: string; host: string; shareName: string; accessLevel: string; anonymousAccess?: boolean | null; smbDialect?: string | null; signingRequired?: boolean | null; source: string }>;
}

export default function Page() {
  const [data, setData] = useState<SmbData>({ items: [] });
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<SmbData>("/ad/smb"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load SMB data.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="SMB Posture" title="SMB Posture" body="Share inventory, permission metadata, dialect and signing posture. Inventory only — share contents are never browsed or downloaded." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      <Card>
        {data.items.length === 0 ? (
          <EmptyState title="No shares recorded" body="Shares appear after an SMB_POSTURE collection." />
        ) : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Host</th><th>Share</th><th>Access</th><th>Anonymous</th><th>Dialect</th><th>Signing</th><th>Source</th></tr></thead>
            <tbody>
              {data.items.map((s) => (
                <tr key={s.id} className="border-t border-slate-800">
                  <td className="py-1.5">{s.host}</td>
                  <td>{s.shareName}</td>
                  <td><Badge>{s.accessLevel}</Badge></td>
                  <td>{s.anonymousAccess === null || s.anonymousAccess === undefined ? "unknown" : s.anonymousAccess ? "YES" : "no"}</td>
                  <td>{s.smbDialect ?? "—"}</td>
                  <td>{s.signingRequired === null || s.signingRequired === undefined ? "unknown" : s.signingRequired ? "required" : "NOT required"}</td>
                  <td className="text-slate-500">{s.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
