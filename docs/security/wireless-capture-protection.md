# Wireless Capture Protection (Prompt 19 §26–§30/§84/§85)

Captures are hostile content: they are attacker-influenced byte streams
that may contain credentials, personal data and malformed frames.

## Intake

- **Format is proven from magic bytes** (pcap `d4c3b2a1…` / pcapng
  section header), never from the file name or extension (§27).
- **Size budget refuses before parsing** (§61/§85): oversized captures
  are rejected at intake, not truncated into the parser.
- **Header sanity** (§84): truncated or internally inconsistent headers
  fail safely; parsers fail closed and record a `parserFailures` metric
  instead of guessing.
- The **SHA-256 is the identity** (§26): a declared hash that does not
  match the content refuses the upload; the same hash dedupes to the
  existing record per workspace.

## Storage & access

- Raw bytes live in protected object storage behind an artifact
  reference (§29); database rows carry metadata only.
- A capture must be **APPROVED** before any adapter may analyze it, and
  adapters receive the artifact reference as their sole file argument.
- The raw reference is an elevated datum (§30): ordinary views hide it,
  and every elevated read writes a `WIRELESS_CAPTURE_ACCESSED` audit
  record.
- Parsers extract bounded metadata only (fixed tshark field set, summary
  counters). Authentication material is counted, never extracted (§67);
  planted credentials in fixtures provably appear in no persisted record.
