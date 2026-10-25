"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card } from "@zerosweep/ui";

/**
 * Group detail (Prompt 15 §94): privilege classification (derived
 * from the group SID/RID by policy, §59) and evidence-backed
 * membership, including nested groups (§65).
 */
interface GroupDetail {
  id: string; name: string; groupScope: string; groupType: string; privilegeClass: string; memberCount: number;
  members: Array<{ memberType: string; memberRef: string; source: string; confidence: string }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [group, setGroup] = useState<GroupDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setGroup(await apiFetch<GroupDetail>(`/ad/groups/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the group.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <p className="text-sm text-red-400">{error}</p>;
  if (!group) return <p className="text-sm text-slate-400">Loading…</p>;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Directory Group" title={group.name} body={`${group.groupScope} ${group.groupType} group · ${group.memberCount} direct members recorded`} />
      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Privilege classification</h2>
        <p className="text-sm text-slate-300">
          <Badge>{group.privilegeClass}</Badge>
          <span className="block text-xs text-slate-500 mt-1">
            Classification follows the well-known group SID/RID by policy — never the display name, which is attacker-controlled text.
            Effective membership resolves nested groups cycle-safely (§65).
          </span>
        </p>
      </Card>
      <Card>
        <h2 className="text-base font-semibold text-slate-100 mb-2">Members (evidence-backed edges, §33)</h2>
        {group.members.length === 0 ? <p className="text-sm text-slate-400">No members recorded.</p> : (
          <ul className="text-sm space-y-1">
            {group.members.map((m, i) => (
              <li key={i} className="text-slate-300">
                <Badge>{m.memberType}</Badge> <span className="font-mono text-xs">{m.memberRef}</span>{" "}
                <span className="text-slate-500">via {m.source} · confidence {m.confidence}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
