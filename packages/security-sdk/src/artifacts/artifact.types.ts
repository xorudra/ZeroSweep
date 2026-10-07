export interface ArtifactMetadata {
  id: string;
  type: "RAW_OUTPUT" | "SCREENSHOT" | "XML" | "JSON" | "JSONL" | "HTML" | "LOG" | "REPORT" | "OTHER";
  contentType: string;
  size: number;
  checksum: string; // sha256 hex
  storageKey: string; // object-storage key — large output never lives in Postgres
  createdAt: string;
}
