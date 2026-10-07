import { createHash } from "node:crypto";

/**
 * Artifact flow (Prompt 4 §31): tool output goes to object storage, never
 * into Postgres in bulk. Production uses the MinIO/S3 store wired in index;
 * this in-memory implementation backs tests and local dev without infra.
 * Every artifact record carries storage key, checksum, size and content type.
 */
export interface StoredArtifact {
  storageKey: string;
  checksum: string;
  size: number;
  contentType: string;
}

export interface ObjectStore {
  put(storageKey: string, content: string, contentType: string): Promise<StoredArtifact>;
  get(storageKey: string): Promise<string | undefined>;
}

export class InMemoryObjectStore implements ObjectStore {
  private readonly objects = new Map<string, string>();

  async put(storageKey: string, content: string, contentType: string): Promise<StoredArtifact> {
    this.objects.set(storageKey, content);
    return {
      storageKey,
      checksum: createHash("sha256").update(content).digest("hex"),
      size: Buffer.byteLength(content, "utf8"),
      contentType,
    };
  }

  async get(storageKey: string): Promise<string | undefined> {
    return this.objects.get(storageKey);
  }
}

export function rawArtifactKey(scanId: string, executionId: string, fileName = "raw.json"): string {
  return `scans/${scanId}/executions/${executionId}/${fileName}`;
}
