import { createHash, createHmac } from "node:crypto";
import type { ObjectStore, StoredArtifact } from "./object-store";

/**
 * S3-compatible ObjectStore (Prompt 38 §58–§60), implemented over
 * Node's fetch with AWS Signature V4 — no SDK dependency. Works
 * against MinIO and any S3-compatible endpoint. Buckets are private by
 * default: the store only ever addresses its one configured bucket
 * with its own least-privilege credentials, and never mints public or
 * presigned URLs (short-lived access links, where a product flow needs
 * them, are issued by the API under its own authorization, §60).
 *
 * Credentials come from the worker's environment (secret references
 * resolved by the deployment, §21–§24) — never from job payloads.
 */
export interface S3ObjectStoreConfig {
  endpoint: string; // e.g. http://127.0.0.1:9000
  bucket: string;
  accessKey: string;
  secretKey: string;
  region?: string;
}

function hmac(key: Buffer | string, data: string): Buffer {
  return createHmac("sha256", key).update(data, "utf8").digest();
}
function sha256(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export class S3ObjectStore implements ObjectStore {
  private readonly region: string;
  private bucketReady: Promise<void> | undefined;

  constructor(private readonly config: S3ObjectStoreConfig) {
    this.region = config.region ?? "us-east-1";
  }

  /** Configuration from environment; returns undefined when object
   *  storage is not configured on this worker (callers keep the
   *  labelled in-memory store for tests/local dev without infra). */
  static fromEnv(env: NodeJS.ProcessEnv = process.env): S3ObjectStore | undefined {
    const endpoint = env.MINIO_ENDPOINT;
    const accessKey = env.MINIO_ACCESS_KEY ?? env.MINIO_ROOT_USER;
    const secretKey = env.MINIO_SECRET_KEY ?? env.MINIO_ROOT_PASSWORD;
    if (!endpoint || !accessKey || !secretKey) return undefined;
    return new S3ObjectStore({
      endpoint, accessKey, secretKey,
      bucket: env.MINIO_BUCKET ?? "dsrclone-artifacts",
      region: env.MINIO_REGION ?? "us-east-1",
    });
  }

  private async request(method: "PUT" | "GET" | "HEAD", key: string, body?: Buffer, contentType?: string): Promise<Response> {
    const url = new URL(`${this.config.endpoint.replace(/\/$/, "")}/${this.config.bucket}/${key.split("/").map(encodeURIComponent).join("/")}`);
    const payloadHash = sha256(body ?? "");
    const now = new Date();
    const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
    const dateStamp = amzDate.slice(0, 8);
    const headers: Record<string, string> = {
      host: url.host,
      "x-amz-content-sha256": payloadHash,
      "x-amz-date": amzDate,
      ...(contentType ? { "content-type": contentType } : {}),
    };
    const signedHeaders = Object.keys(headers).sort().join(";");
    const canonicalHeaders = Object.keys(headers).sort().map((h) => `${h}:${headers[h]!.trim()}\n`).join("");
    const canonicalRequest = [method, url.pathname, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
    const scope = `${dateStamp}/${this.region}/s3/aws4_request`;
    const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonicalRequest)].join("\n");
    const kDate = hmac(`AWS4${this.config.secretKey}`, dateStamp);
    const kRegion = hmac(kDate, this.region);
    const kService = hmac(kRegion, "s3");
    const kSigning = hmac(kService, "aws4_request");
    const signature = createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");
    headers.authorization = `AWS4-HMAC-SHA256 Credential=${this.config.accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    return fetch(url, { method, headers, body: body ? new Uint8Array(body) : undefined });
  }

  private async ensureBucket(): Promise<void> {
    this.bucketReady ??= (async () => {
      const head = await this.request("HEAD", "");
      if (head.status === 404) {
        // Create the bucket (private by default — no ACL header is sent,
        // so the bucket inherits the provider's private default, §60).
        const url = new URL(`${this.config.endpoint.replace(/\/$/, "")}/${this.config.bucket}`);
        const res = await fetch(url, { method: "PUT", headers: await this.bucketHeaders(url) });
        if (!res.ok && res.status !== 409) throw new Error(`bucket create failed: ${res.status}`);
      } else if (!head.ok && head.status !== 301) {
        throw new Error(`bucket head failed: ${head.status}`);
      }
    })();
    return this.bucketReady;
  }

  private async bucketHeaders(url: URL): Promise<Record<string, string>> {
    const payloadHash = sha256("");
    const now = new Date();
    const amzDate = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
    const dateStamp = amzDate.slice(0, 8);
    const headers: Record<string, string> = { host: url.host, "x-amz-content-sha256": payloadHash, "x-amz-date": amzDate };
    const signedHeaders = Object.keys(headers).sort().join(";");
    const canonicalHeaders = Object.keys(headers).sort().map((h) => `${h}:${headers[h]!.trim()}\n`).join("");
    const canonicalRequest = ["PUT", url.pathname, "", canonicalHeaders, signedHeaders, payloadHash].join("\n");
    const scope = `${dateStamp}/${this.region}/s3/aws4_request`;
    const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonicalRequest)].join("\n");
    const kSigning = hmac(hmac(hmac(hmac(`AWS4${this.config.secretKey}`, dateStamp), this.region), "s3"), "aws4_request");
    const signature = createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");
    headers.authorization = `AWS4-HMAC-SHA256 Credential=${this.config.accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
    return headers;
  }

  async put(storageKey: string, content: string, contentType: string): Promise<StoredArtifact> {
    await this.ensureBucket();
    const body = Buffer.from(content, "utf8");
    const res = await this.request("PUT", storageKey, body, contentType);
    if (!res.ok) throw new Error(`object store PUT failed: ${res.status} ${await res.text().then((t) => t.slice(0, 200))}`);
    return { storageKey, checksum: sha256(body), size: body.byteLength, contentType };
  }

  async get(storageKey: string): Promise<string | undefined> {
    await this.ensureBucket();
    const res = await this.request("GET", storageKey);
    if (res.status === 404) return undefined;
    if (!res.ok) throw new Error(`object store GET failed: ${res.status}`);
    return res.text();
  }
}
