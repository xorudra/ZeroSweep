import { createHash } from "node:crypto";
import { scanForInjection } from "./injection";
import { redactForAi } from "./redaction";
import type { AiDataClassification } from "./types";

/**
 * Knowledge base + embeddings (Prompt 21 §66–§74, §96/§97).
 * Documents are UNTRUSTED (§72): ingestion caps size, scans for
 * embedded instructions, redacts secrets, and hashes content — the
 * document is stored as data and cited exactly (§73), never obeyed.
 *
 * Embeddings use a deterministic local hashing embedder: reproducible,
 * offline, and honest about what it is (lexical, not a neural semantic
 * model). The tenant-isolation contract does NOT depend on the
 * embedder: retrieval filters by workspaceId metadata FIRST (§68) and
 * only then ranks by similarity — a cross-tenant vector can never
 * surface, even if it is the closest match (§96).
 */

export const EMBEDDING_DIMENSIONS = 128;
export const MAX_KNOWLEDGE_DOCUMENT_BYTES = 256_000;

export function embedText(text: string): number[] {
  const vec = new Array<number>(EMBEDDING_DIMENSIONS).fill(0);
  const tokens = text.toLowerCase().match(/[a-z0-9][a-z0-9-]{1,}/g) ?? [];
  for (const t of tokens) {
    const h = createHash("sha256").update(t).digest();
    const idx = h.readUInt16BE(0) % EMBEDDING_DIMENSIONS;
    vec[idx] += h[2]! / 255;
  }
  const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0)) || 1;
  return vec.map((v) => Number((v / norm).toFixed(6)));
}

export function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0;
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) dot += a[i]! * b[i]!;
  return dot;
}

export interface KnowledgeIngestionResult {
  accepted: boolean;
  reason?: string;
  content: string;
  contentHash: string;
  injectionFlags: number;
  redactionCount: number;
}

/** §72 ingestion: oversized/malformed rejected; hostile content sanitized, flagged, kept as data. */
export function ingestKnowledgeDocument(raw: string): KnowledgeIngestionResult {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    return { accepted: false, reason: "document is empty or not text", content: "", contentHash: "", injectionFlags: 0, redactionCount: 0 };
  }
  if (Buffer.byteLength(raw, "utf8") > MAX_KNOWLEDGE_DOCUMENT_BYTES) {
    return { accepted: false, reason: `document exceeds ${MAX_KNOWLEDGE_DOCUMENT_BYTES} bytes (§72)`, content: "", contentHash: "", injectionFlags: 0, redactionCount: 0 };
  }
  if (raw.includes("\u0000")) {
    return { accepted: false, reason: "document contains NUL bytes (malformed/binary, §72)", content: "", contentHash: "", injectionFlags: 0, redactionCount: 0 };
  }
  const scan = scanForInjection(raw);
  const red = redactForAi(raw);
  return {
    accepted: true,
    content: red.text,
    contentHash: createHash("sha256").update(red.text).digest("hex"),
    injectionFlags: scan.detections.length,
    redactionCount: red.count,
  };
}

export interface VectorRecord {
  workspaceId: string;
  sourceType: string;
  sourceId: string;
  classification: AiDataClassification;
  vector: number[];
}

/**
 * §68/§96 tenant-scoped retrieval: metadata filter FIRST (workspace +
 * optional classification ceiling), similarity SECOND. Returns source
 * ids so answers can cite the exact document/record (§73).
 */
export function searchVectors<T extends VectorRecord>(
  records: T[],
  query: { workspaceId: string; text: string; maxClassification?: AiDataClassification; limit?: number },
): { record: T; score: number }[] {
  const rank = (c: AiDataClassification) => ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"].indexOf(c);
  const ceiling = query.maxClassification ? rank(query.maxClassification) : rank("SECRET");
  const scoped = records.filter((r) => r.workspaceId === query.workspaceId && rank(r.classification) <= ceiling);
  const qv = embedText(query.text);
  return scoped
    .map((record) => ({ record, score: cosineSimilarity(qv, record.vector) }))
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, query.limit ?? 5);
}
