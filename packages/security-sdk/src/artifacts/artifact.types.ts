export interface ArtifactMetadata {
  id: string;
  type: "RAW_OUTPUT" | "SCREENSHOT" | "XML" | "JSON" | "JSONL" | "HTML" | "LOG" | "REPORT" | "OTHER";
  contentType: string;
  size: number;
  checksum: string; // sha256 hex
  storageKey: string; // object-storage key — large output never lives in Postgres
  createdAt: string;
}

/**
 * Screenshot artifact preparation (Prompt 5 §34): EyeWitness/gowitness are
 * NOT integrated yet; this descriptor is the contract future screenshot
 * adapters will emit. Screenshots live in object storage only — the
 * storageKey follows the scan/execution layout, never a public URL.
 */
export interface ScreenshotArtifact extends ArtifactMetadata {
  type: "SCREENSHOT";
  assetId?: string;
  endpointUrl?: string;
}
