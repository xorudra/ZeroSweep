import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  buildReportSnapshot, reportFindingsFixture, type ReportSnapshotDocument,
} from "@dsrclone/security-sdk";
import { InMemoryObjectStore } from "./artifacts/object-store";
import {
  ReportExportRunner, type ReportExportJob, type ReportJobStore, type ReportSnapshotRecord,
} from "./executors/report-runner";

/**
 * Prompt 20 worker e2e: queued report exports render from the stored
 * snapshot only (§95), artifacts land in object storage with SHA-256,
 * secret-shaped fixture values never reach any artifact (§63/§109),
 * and a tampered snapshot is refused.
 */

class MemReportStore implements ReportJobStore {
  exports: ReportExportJob[] = [];
  snapshots: ReportSnapshotRecord[] = [];
  async claimNextExport(): Promise<ReportExportJob | null> {
    const job = this.exports.find((e) => e.status === "QUEUED");
    if (job) job.status = "RUNNING";
    return job ?? null;
  }
  async getSnapshotForReport(reportId: string) {
    return this.snapshots.find((s) => s.reportId === reportId) ?? null;
  }
  async markExportReady(id: string, patch: { storageLocation: string; checksum: string; sizeBytes: number }) {
    const job = this.exports.find((e) => e.id === id)!;
    Object.assign(job, { status: "READY", ...patch });
  }
  async markExportFailed(id: string, error: string) {
    const job = this.exports.find((e) => e.id === id)!;
    Object.assign(job, { status: "FAILED", error });
  }
}

function snapshotFor(reportId: string): { snapshot: ReportSnapshotRecord; document: ReportSnapshotDocument } {
  const { document, contentHash } = buildReportSnapshot({
    reportId, title: "Quarterly Security Report", type: "EXECUTIVE", generatedBy: "u-admin",
    generatedAt: new Date("2026-10-07T00:00:00Z"), version: "v1", classification: "CONFIDENTIAL",
    findings: reportFindingsFixture(),
  });
  return { snapshot: { id: `snap-${reportId}`, reportId, workspaceId: "ws-1", data: document, contentHash }, document };
}

describe("report export runner (§95)", () => {
  it("renders all four formats from the snapshot; checksums match the stored bytes", async () => {
    const store = new MemReportStore();
    const objects = new InMemoryObjectStore();
    const { snapshot } = snapshotFor("rep-1");
    store.snapshots.push(snapshot);
    for (const format of ["PDF", "HTML", "JSON", "CSV"] as const) {
      store.exports.push({ id: `exp-${format}`, reportId: "rep-1", workspaceId: "ws-1", format, status: "QUEUED" });
    }
    const runner = new ReportExportRunner(store, objects);
    expect(await runner.runOnce()).toBe(4);
    for (const job of store.exports) {
      expect(job.status).toBe("READY");
      const bytes = await objects.get((job as unknown as { storageLocation: string }).storageLocation);
      expect(bytes).toBeDefined();
      expect(createHash("sha256").update(bytes!).digest("hex")).toBe((job as unknown as { checksum: string }).checksum);
    }
    const pdf = await objects.get("reports/ws-1/rep-1/report.pdf");
    expect(pdf!.startsWith("%PDF-1.4")).toBe(true);
    const json = JSON.parse((await objects.get("reports/ws-1/rep-1/report.json"))!);
    expect(json.findings).toHaveLength(1);
    expect(json.classification).toBe("CONFIDENTIAL");
  });

  it("no secret-shaped fixture value reaches any artifact (§63/§109)", async () => {
    const store = new MemReportStore();
    const objects = new InMemoryObjectStore();
    const { snapshot } = snapshotFor("rep-2");
    store.snapshots.push(snapshot);
    for (const format of ["PDF", "HTML", "JSON", "CSV"] as const) {
      store.exports.push({ id: `exp2-${format}`, reportId: "rep-2", workspaceId: "ws-1", format, status: "QUEUED" });
    }
    await new ReportExportRunner(store, objects).runOnce();
    for (const format of ["pdf", "html", "json", "csv"]) {
      const bytes = (await objects.get(`reports/ws-1/rep-2/report.${format}`))!;
      for (const marker of ["FIXTURE_TOKEN_VALUE", "FIXTURE_SESSION_VALUE", "FIXTUREKEYMATERIAL", "hunter2fixture", "BEGIN PRIVATE KEY"]) {
        expect(bytes.includes(marker)).toBe(false);
      }
    }
  });

  it("deterministic: rendering the same snapshot twice yields identical bytes (snapshot immutability §56/§108)", async () => {
    const store = new MemReportStore();
    const objects = new InMemoryObjectStore();
    const { snapshot, document } = snapshotFor("rep-3");
    // A copy of the snapshot as stored — later edits to any live data cannot reach it.
    store.snapshots.push(JSON.parse(JSON.stringify(snapshot)) as ReportSnapshotRecord);
    store.exports.push({ id: "exp3", reportId: "rep-3", workspaceId: "ws-1", format: "JSON", status: "QUEUED" });
    await new ReportExportRunner(store, objects).runOnce();
    const bytes = (await objects.get("reports/ws-1/rep-3/report.json"))!;
    expect(bytes).toBe(JSON.stringify(document, null, 2));
  });

  it("tampered snapshot is refused and the export fails honestly", async () => {
    const store = new MemReportStore();
    const objects = new InMemoryObjectStore();
    const { snapshot } = snapshotFor("rep-4");
    const tampered = { ...snapshot, data: { ...(snapshot.data as object), title: "Forged" } };
    store.snapshots.push(tampered);
    store.exports.push({ id: "exp4", reportId: "rep-4", workspaceId: "ws-1", format: "JSON", status: "QUEUED" });
    await new ReportExportRunner(store, objects).runOnce();
    expect(store.exports[0]!.status).toBe("FAILED");
    expect((store.exports[0] as unknown as { error: string }).error).toContain("content hash mismatch");
  });

  it("missing snapshot fails the export instead of fabricating a report", async () => {
    const store = new MemReportStore();
    const objects = new InMemoryObjectStore();
    store.exports.push({ id: "exp5", reportId: "rep-none", workspaceId: "ws-1", format: "PDF", status: "QUEUED" });
    await new ReportExportRunner(store, objects).runOnce();
    expect(store.exports[0]!.status).toBe("FAILED");
  });
});
