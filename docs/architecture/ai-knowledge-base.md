# AI knowledge base (Prompt 21 §70–§74)

## Sources (§70/§71)

Approved internal remediation documents, security standards, product
security guidance and organization policies. Each `KnowledgeDocument`
records workspace, title, source, classification, version, content
hash and status.

## Ingestion (§72)

Documents are **untrusted input**. Ingestion:

- rejects empty, NUL-bearing (binary/malformed) and oversized
  (> 256 KB) documents;
- scans for embedded instruction text (prompt-injection patterns) —
  hits are **flagged and counted**, stored as document metadata, and
  the content remains data;
- redacts secrets before storage (§15);
- hashes the sanitized content (SHA-256) for provenance;
- creates a tenant-scoped `AiEmbedding` for retrieval.

## Citation & freshness (§73/§74)

Answers using knowledge documents cite the exact document id.
Freshness is tracked via version + hash; internal CVE/KEV/EPSS
records (Prompt 11 intel) are preferred over document text for
vulnerability facts, because intelligence feeds go stale.
