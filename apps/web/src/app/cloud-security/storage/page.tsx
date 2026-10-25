"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Cloud storage & databases (Prompt 14 §83/§43–§45). Configuration
 * analysis only: public access, encryption, logging, versioning,
 * backups and TLS posture from inventory metadata. Object contents
 * are never listed or downloaded, and databases are never connected
 * to (§13/§45).
 */
interface ResourceRow {
  id: string; provider: string; resourceType: string; name: string;
  region?: string | null; exposure: string; status: string;
}

const STORAGE_TYPES = ["STORAGE", "BUCKET", "S3", "BLOB"];
const DATABASE_TYPES = ["RDS", "SQL", "DATABASE", "DYNAMODB", "COSMOS", "SPANNER", "FIRESTORE"];

function isStorage(r: ResourceRow) { return STORAGE_TYPES.some((t) => r.resourceType.includes(t)); }
function isDatabase(r: ResourceRow) { return DATABASE_TYPES.some((t) => r.resourceType.includes(t)); }

export default function Page() {
  const [items, setItems] = useState<ResourceRow[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: ResourceRow[] }>("/cloud/resources");
      setItems((data.items ?? []).filter((r) => isStorage(r) || isDatabase(r)));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const storage = items.filter(isStorage);
  const databases = items.filter((r) => isDatabase(r) && !isStorage(r));

  const section = (title: string, rows: ResourceRow[], empty: string) => (
    <Card>
      <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h2>
      {rows.length === 0 && <EmptyState title={empty} body="Run a cloud inventory or baseline scan on a registered account." />}
      <div className="divide-y divide-slate-800">
        {rows.map((r) => (
          <div key={r.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
            <Link className="text-cyan-300 hover:underline" href={`/cloud-security/resources/${r.id}`}>{r.name}</Link>
            <Badge>{r.provider}</Badge>
            <span className="font-mono text-xs text-slate-400">{r.resourceType}</span>
            <span className="text-slate-400">{r.region ?? "global"}</span>
            <Badge>{r.exposure}</Badge>
            {r.status !== "ACTIVE" && <Badge>{r.status}</Badge>}
          </div>
        ))}
      </div>
    </Card>
  );

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Cloud Storage" title="Storage & Databases" body="Posture from configuration metadata: public access, encryption, logging, versioning, backup and TLS facts. The detailed per-resource facts live on each resource page (access-audited)." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {section("Storage (buckets / accounts)", storage, "No storage resources inventoried")}
      {section("Databases", databases, "No database resources inventoried")}
    </div>
  );
}
