# tcpdump (bounded packet capture)

**Adapter:** `TcpdumpCaptureAdapter`, executable `tcpdump`, capability
`PACKET_CAPTURE`. Risk: PASSIVE. Worker: `PACKET_ANALYSIS` with the
`PACKET_CAPTURE` capability.

## Governance (§44/§47/§48)

- Approved **controlled test environments only**. An explicit
  interface name is required — `any` is refused — and no BPF/filter
  expression field exists (filters would be raw expressions, §82).
- Duration is clamped to the network budget
  (`maxPacketCaptureDurationSeconds`, default 300 s), packet count is
  capped, exactly one capture file is produced (`-G`/`-W 1`/`-c`).
- Capture output becomes a `PacketCaptureArtifact` metadata row
  pointing at object storage. Raw access requires OWNER/ADMIN and is
  audited on every call (`RAW_PCAP_ACCESSED`); retention follows the
  capture policy. The adapter's parser deliberately performs NO
  analysis — that is tshark's offline job (§45).

## Health

UNAVAILABLE when the binary is absent, and UNAVAILABLE_FOR_WORKER on
workers without the capture capability.
