import { createHash } from "node:crypto";
import { renderReport, type ReportSnapshotDocument, type ReportFormat } from "@zerosweep/security-sdk";
import type { ObjectStore } from "../artifacts/object-store";

/**
 * Report export runner (Prompt 20 §95). Report generation is
 * asynchronous: the API builds the immutable snapshot (§56) and queues
 * ReportExport rows; this runner claims QUEUED exports, renders the
 * STORED snapshot document into the requested format, and stores the
 * artifact in object storage with its SHA-256. It never queries live
 * findings — a report renders exactly the snapshot it was issued from,
 * so a finding that changes after issuance cannot alter the artifact.
 */

export interface ReportExportJob {
  id: string;
  reportId: string;
  workspaceId: string;
  format: ReportFormat;
  status: string;
}

export interface ReportSnapshotRecord {
  id: string;
  reportId: string;
  workspaceId: string;
  data: unknown;
  contentHash: string;
}

export interface ReportJobStore {
  claimNextExport(): Promise<ReportExportJob | null>;
  getSnapshotForReport(reportId: string): Promise<ReportSnapshotRecord | null>;
  markExportReady(id: string, patch: { storageLocation: string; checksum: string; sizeBytes: number }): Promise<void>;
  markExportFailed(id: string, error: string): Promise<void>;
}

const CONTENT_TYPES: Record<ReportFormat, string> = {
  PDF: "application/pdf",
  HTML: "text/html; charset=utf-8",
  JSON: "application/json",
  CSV: "text/csv; charset=utf-8",
};

export function reportArtifactKey(workspaceId: string, reportId: string, format: ReportFormat): string {
  return `reports/${workspaceId}/${reportId}/report.${format.toLowerCase()}`;
}

export class ReportExportRunner {
  constructor(
    private readonly store: ReportJobStore,
    private readonly objects: ObjectStore,
  ) {}

  /** Render one export. Returns the stored artifact descriptor. */
  async runExport(job: ReportExportJob): Promise<{ storageLocation: string; checksum: string; sizeBytes: number }> {
    try {
      const snapshot = await this.store.getSnapshotForReport(job.reportId);
      if (!snapshot) throw new Error(`report ${job.reportId} has no snapshot — generation must precede export (§56/§95)`);
      // Integrity: the snapshot document must hash to its recorded content hash.
      const actual = createHash("sha256").update(JSON.stringify(snapshot.data)).digest("hex");
      if (actual !== snapshot.contentHash) throw new Error("snapshot content hash mismatch — refusing to render a tampered snapshot");
      const rendered = renderReport(snapshot.data as ReportSnapshotDocument, job.format);
      const content = typeof rendered.content === "string" ? rendered.content : rendered.content.toString("latin1");
      const key = reportArtifactKey(job.workspaceId, job.reportId, job.format);
      const stored = await this.objects.put(key, content, CONTENT_TYPES[job.format]);
      await this.store.markExportReady(job.id, { storageLocation: stored.storageKey, checksum: stored.checksum, sizeBytes: stored.size });
      return { storageLocation: stored.storageKey, checksum: stored.checksum, sizeBytes: stored.size };
    } catch (err) {
      await this.store.markExportFailed(job.id, (err as Error).message);
      throw err;
    }
  }

  /** Drain the queue once (bounded). Returns how many exports were processed. */
  async runOnce(limit = 25): Promise<number> {
    let processed = 0;
    for (let i = 0; i < limit; i++) {
      const job = await this.store.claimNextExport();
      if (!job) break;
      processed++;
      try {
        await this.runExport(job);
      } catch {
        // failure already recorded on the export row; continue draining
      }
    }
    return processed;
  }
}
