# Network Packet Analysis (Prompt 33 §83–§93)

Packet analysis works over PCAP / Wireshark-compatible captures via
tshark/tcpdump governance:

- A capture requires an authorized interface reference, the
  CREATE_PACKET_CAPTURE permission, and explicit bounds: duration
  (≤ 3600s platform max), size (≤ 2 GiB), and workspace storage quota.
  Oversized requests are REJECTED, not clamped.
- Capture is PASSIVE by default and always: the platform records and
  summarizes; it never injects, modifies or replays traffic. No such
  capability exists in the codebase.
- PCAP files are sensitive evidence in restricted object storage.
  Viewing is a separate permission (VIEW_PACKET_CAPTURE); raw bytes
  never flow through the API or UI.
- Summaries are built from structured protocol metadata and REDACT
  credentials, session tokens and payload content before they exist.
- Packet findings stay inside the authorized capture context:
  plaintext protocols, weak protocols, unexpected services, TLS
  metadata, DNS anomalies.

In this deployment the capture transport is NOT_CONFIGURED: capture
requests are recorded with their bounds and honestly reported as not
executed.
