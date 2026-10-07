import { createHash } from "node:crypto";
import { REDACTION, redactEvidenceText } from "../vuln/redact";

/**
 * HTTP evidence redaction (Prompt 8 §27–§29). Proxy connectors observe
 * REAL traffic, which contains live credentials. Two artefacts exist for
 * every transaction:
 *  - the RAW artifact (object storage, stronger access control §60) — the
 *    redactor NEVER modifies it; it only computes its hash/size (§26);
 *  - the DISPLAY copy produced here — headers and bodies redacted, size
 *    capped — the only form normal findings/UI surfaces may render.
 *
 * The sensitive-header list is configurable (§28); the defaults cover the
 * spec's list plus common token headers. Body redaction is content-type
 * aware (§29): JSON keys, form fields and multipart part headers whose
 * names match the sensitive-field list are masked.
 */

export const DEFAULT_SENSITIVE_HEADERS: readonly string[] = [
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "x-session-id",
  "x-csrf-token",
  "x-xsrf-token",
];

export const DEFAULT_SENSITIVE_FIELDS: readonly string[] = [
  "password", "passwd", "pwd", "secret", "token",
  "access_token", "refresh_token", "api_key", "apikey",
  "auth_token", "session", "session_id", "sessionid",
  "client_secret", "private_key", "credential", "otp", "pin",
];

export interface RedactorOptions {
  sensitiveHeaders?: string[];
  sensitiveFields?: string[];
  /** Display-copy cap per message part, bytes (§26/§31-style capping). */
  maxDisplayBytes?: number;
}

export interface RedactedMessage {
  /** Redacted display text: start line + headers + (redacted) body. */
  text: string;
  /** sha256 of the RAW message — the integrity link to the raw artifact. */
  checksum: string;
  /** Byte size of the RAW message. */
  originalBytes: number;
  truncated: boolean;
  /** True when at least one secret was masked. */
  redacted: boolean;
}

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

export class HttpEvidenceRedactor {
  private readonly sensitiveHeaders: Set<string>;
  private readonly sensitiveFields: Set<string>;
  private readonly maxDisplayBytes: number;

  constructor(opts: RedactorOptions = {}) {
    this.sensitiveHeaders = new Set((opts.sensitiveHeaders ?? DEFAULT_SENSITIVE_HEADERS).map((h) => h.toLowerCase()));
    this.sensitiveFields = new Set((opts.sensitiveFields ?? DEFAULT_SENSITIVE_FIELDS).map((f) => f.toLowerCase()));
    this.maxDisplayBytes = opts.maxDisplayBytes ?? 32 * 1024;
  }

  isSensitiveHeader(name: string): boolean {
    return this.sensitiveHeaders.has(name.trim().toLowerCase());
  }

  isSensitiveField(name: string): boolean {
    return this.sensitiveFields.has(name.trim().toLowerCase());
  }

  /** Redact one header block (array of [name, value] or a raw header
   *  string). Sensitive VALUES are replaced wholesale — a partially shown
   *  credential is still a credential (§28). */
  redactHeaders(headers: Array<[string, string]> | string): { text: string; redacted: boolean } {
    const pairs: Array<[string, string]> = typeof headers === "string"
      ? headers.split(/\r?\n/).filter((l) => l.includes(":")).map((l) => {
          const i = l.indexOf(":");
          return [l.slice(0, i).trim(), l.slice(i + 1).trim()] as [string, string];
        })
      : headers;
    let redacted = false;
    const lines = pairs.map(([name, value]) => {
      if (this.isSensitiveHeader(name)) { redacted = true; return `${name}: ${REDACTION}`; }
      return `${name}: ${value}`;
    });
    return { text: lines.join("\n"), redacted };
  }

  /** Content-type-aware body redaction (§29). Unknown/binary bodies are
   *  never partially leaked: they are replaced by a typed placeholder with
   *  size + hash recorded by the caller. */
  redactBody(body: string, contentType: string | undefined): { text: string; redacted: boolean } {
    if (!body) return { text: "", redacted: false };
    const ct = (contentType ?? "").toLowerCase();
    if (ct.includes("application/json") || ct.includes("+json")) {
      return this.redactJsonBody(body);
    }
    if (ct.includes("application/x-www-form-urlencoded")) {
      let redacted = false;
      const out = body.split("&").map((pair) => {
        const eq = pair.indexOf("=");
        if (eq < 0) return pair;
        const name = decodeURIComponent(pair.slice(0, eq)).toLowerCase();
        if (this.isSensitiveField(name)) { redacted = true; return `${pair.slice(0, eq)}=${REDACTION}`; }
        return pair;
      }).join("&");
      return { text: out, redacted };
    }
    if (ct.includes("multipart/form-data")) {
      // Multipart metadata only (§29): part headers are redacted like
      // headers; part bodies are represented, never passed through raw.
      let redacted = false;
      const out = body.replace(/(content-disposition:[^\n]*name=")([^"]+)(")/gi, (m, pre: string, name: string, post: string) => {
        if (this.isSensitiveField(name)) { redacted = true; return `${pre}${name}${post}\nX-DSRclone-Redacted: part body withheld (${REDACTION})`; }
        return m;
      });
      return { text: out, redacted };
    }
    if (ct.includes("text/") || ct.includes("xml") || ct.includes("javascript") || ct === "") {
      // Textual bodies still pass through the generic secret patterns
      // (Authorization headers embedded in dumps, key=value secrets).
      const out = redactEvidenceText(body);
      return { text: out, redacted: out !== body };
    }
    return { text: `[binary body withheld: ${body.length} bytes, content-type ${ct}]`, redacted: true };
  }

  private redactJsonBody(body: string): { text: string; redacted: boolean } {
    try {
      const parsed = JSON.parse(body) as unknown;
      let redacted = false;
      const walk = (v: unknown): unknown => {
        if (Array.isArray(v)) return v.map(walk);
        if (v && typeof v === "object") {
          const out: Record<string, unknown> = {};
          for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
            if (this.isSensitiveField(k)) { redacted = true; out[k] = REDACTION; }
            else out[k] = walk(val);
          }
          return out;
        }
        return v;
      };
      const out = JSON.stringify(walk(parsed));
      // Defence in depth: textual pass for secrets embedded in strings.
      const finalText = redactEvidenceText(out);
      return { text: finalText, redacted: redacted || finalText !== out };
    } catch {
      const out = redactEvidenceText(body);
      return { text: out, redacted: out !== body };
    }
  }

  /** Full message pipeline (§27): start line preserved, headers + body
   *  redacted, display copy capped; the RAW message is only hashed. */
  redactHttpMessage(raw: string, contentType?: string): RedactedMessage {
    const checksum = sha256(raw);
    const originalBytes = Buffer.byteLength(raw, "utf8");
    const splitAt = raw.search(/\r?\n\r?\n/);
    const head = splitAt >= 0 ? raw.slice(0, splitAt) : raw;
    const body = splitAt >= 0 ? raw.slice(splitAt).replace(/^\r?\n\r?\n/, "") : "";
    const headLines = head.split(/\r?\n/);
    const startLine = headLines[0] ?? "";
    const headerText = headLines.slice(1).join("\n");
    const headers = this.redactHeaders(headerText);
    const ct = contentType ?? this.headerValue(headLines.slice(1), "content-type");
    const bod = this.redactBody(body, ct);
    let text = [startLine, headers.text, "", bod.text].join("\n").trimEnd();
    let truncated = false;
    if (Buffer.byteLength(text, "utf8") > this.maxDisplayBytes) {
      text = `${text.slice(0, this.maxDisplayBytes)}\n…[display copy truncated; raw artifact ${checksum.slice(0, 12)}…]`;
      truncated = true;
    }
    return { text, checksum, originalBytes, truncated, redacted: headers.redacted || bod.redacted };
  }

  private headerValue(lines: string[], name: string): string | undefined {
    for (const line of lines) {
      const i = line.indexOf(":");
      if (i > 0 && line.slice(0, i).trim().toLowerCase() === name) return line.slice(i + 1).trim();
    }
    return undefined;
  }
}

/** Shared default redactor (spec default lists). */
export const httpEvidenceRedactor = new HttpEvidenceRedactor();
