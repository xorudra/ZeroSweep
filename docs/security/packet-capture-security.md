# Packet Capture Security (Prompt 33 §83–§93)

- Capture requires an authorized interface reference (an opaque
  worker-configuration reference — never a raw device path or shell
  fragment), the CREATE_PACKET_CAPTURE permission, bounded duration
  (≤ 3600s), bounded size (≤ 2 GiB) and available storage quota.
  Violations are rejected outright (§151).
- Capture is passive. Traffic injection, modification and replay do
  not exist as capabilities.
- PCAP content is sensitive evidence: restricted object storage,
  separate retention policy, access under VIEW_PACKET_CAPTURE only,
  and raw bytes never traverse the API/UI.
- Summaries are metadata-only (protocol counts, flow metadata, TLS
  versions, DNS outcomes) and are redacted for credentials, session
  tokens and payload content before they are stored (§90). §152's
  test proves unauthorized roles are denied both list and detail.
- Filters are validated as data (length-bounded, metacharacters
  refused) consistent with the platform's no-shell rule (§137).
