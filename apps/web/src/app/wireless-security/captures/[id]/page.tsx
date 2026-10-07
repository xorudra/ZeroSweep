"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card } from "@dsrclone/ui";

/**
 * Wireless capture detail (Prompt 19 §75). Metadata + hash identity
 * + approval state + registered analysis artifacts. Raw bytes never
 * render here; the artifact reference is an elevated datum (§30) —
 * when this page shows it, the access was audited server-side.
 * Authentication material in a capture is a COUNT, never content
 * (§67).
 */
interface CaptureDetail {
  id: string; environmentId: string; name: string; sha256: string; format: string;
  sizeBytes: string; status: string; sanitizationStatus: string; channels: number[];
  createdAt?: string | null; artifactReference?: string | null;
  analysisArtifacts?: Record<string, unknown> | null;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [capture, setCapture] = useState<CaptureDetail | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setCapture(await apiFetch<CaptureDetail>(`/wireless/captures/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to load capture");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const decide = async (decision: "APPROVE" | "REJECT") => {
    try {
      await apiFetch(`/wireless/captures/${params.id}/approve`, {
        method: "POST", body: JSON.stringify({ decision }),
      });
      setNotice(`Capture ${decision === "APPROVE" ? "approved for offline analysis" : "rejected"}.`);
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Decision failed");
    }
  };

  if (error) return <Card><p className="text-sm text-red-300">{error}</p></Card>;
  if (!capture) return <Card><p className="text-sm text-slate-400">Loading…</p></Card>;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Wireless Security" title={capture.name} body="Capture artifact — metadata only; raw bytes stay in protected storage (§29)" />
      {notice && <Card><p className="text-sm text-emerald-300">{notice}</p></Card>}
      <Card>
        <div className="flex flex-wrap gap-2">
          <Badge>{capture.format}</Badge>
          <Badge>{capture.status}</Badge>
          <Badge>sanitization {capture.sanitizationStatus}</Badge>
        </div>
        <dl className="mt-3 space-y-1 text-sm text-slate-300">
          <div>SHA-256 <span className="text-slate-100">{capture.sha256}</span> (identity — proven from content, §26)</div>
          <div>Size {capture.sizeBytes} bytes · channels {capture.channels.join(", ") || "—"} · uploaded {capture.createdAt ?? "—"}</div>
          <div>
            Artifact reference:{" "}
            {capture.artifactReference
              ? <span className="text-slate-100">{capture.artifactReference}</span>
              : <span className="text-slate-500">hidden — requires VIEW_RAW_WIRELESS_CAPTURES; this read was audited (§30)</span>}
          </div>
        </dl>
        {capture.status === "PENDING" && (
          <div className="mt-3 flex gap-2">
            <button className="rounded bg-emerald-600 px-3 py-1.5 text-sm text-white" onClick={() => void decide("APPROVE")}>Approve for analysis</button>
            <button className="rounded bg-slate-700 px-3 py-1.5 text-sm text-white" onClick={() => void decide("REJECT")}>Reject</button>
          </div>
        )}
        <p className="mt-3 text-xs text-slate-500">
          Only APPROVED captures are analyzed, and only offline (tshark / hcxpcapngtool /
          aircrack-ng metadata). Hash-export and cracking modes are not expressible (§20/§23).
        </p>
      </Card>
      {capture.analysisArtifacts && (
        <Card>
          <h2 className="text-base font-semibold text-slate-100">Registered analysis artifacts</h2>
          <pre className="mt-2 overflow-x-auto text-xs text-slate-300">{JSON.stringify(capture.analysisArtifacts, null, 2)}</pre>
        </Card>
      )}
    </div>
  );
}
