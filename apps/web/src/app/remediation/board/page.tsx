"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface BoardCard { caseId: string; findingId: string; status: string; priority: string | null; ownerId: string | null; dueAt: string | null }
interface Board { columns: Record<string, BoardCard[]>; total: number }

const COLUMN_TITLES: Record<string, string> = {
  UNASSIGNED: "Unassigned", PLANNED: "Planned", IN_PROGRESS: "In Progress",
  FIX_CLAIMED: "Fix Claimed", VERIFICATION: "Verification", VERIFIED: "Verified", OVERDUE: "Overdue",
};

/**
 * Remediation board (Prompt 37 §113): Prompt 31 cases grouped into
 * the spec's columns. "Verified" contains only cases the governed
 * verification flow closed — a fix claim sits in its own column.
 */
export default function RemediationBoardPage() {
  const [board, setBoard] = useState<Board | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<Board>("/vulnerability-management/remediation-board").then(setBoard).catch((e: Error) => setError(e.message));
  }, []);
  return (
    <div>
      <PageHeader eyebrow="Remediation" title="Remediation Board" body={`${board?.total ?? 0} remediation cases`} />
      {error && <p role="alert">{error}</p>}
      {board && (
        <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))" }}>
          {Object.entries(board.columns).map(([key, cards]) => (
            <div key={key}>
              <h3>{COLUMN_TITLES[key] ?? key} ({cards.length})</h3>
              <div style={{ display: "grid", gap: 8 }}>
                {cards.map((c) => (
                  <Card key={c.caseId}>
                    <p style={{ fontSize: 13 }}>{c.status}{c.priority ? ` · ${c.priority}` : ""}</p>
                    <p style={{ color: "#666", fontSize: 12 }}>
                      {c.ownerId ? `Owner ${c.ownerId}` : "Unassigned"}
                      {c.dueAt ? ` · Due ${new Date(c.dueAt).toLocaleDateString()}` : ""}
                    </p>
                  </Card>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
