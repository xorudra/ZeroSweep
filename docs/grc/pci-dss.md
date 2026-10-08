# PCI DSS 4.0 in DSRclone (Prompt 26)

Shipped catalog version: PCI_DSS 4.0 (Requirements 1–12).
Requirement IDs/titles are the published reference structure.

Mapping notes (technical strengths):

- Req 2 (no vendor defaults / secure configuration) — PARTIAL via
  TLS + configuration controls.
- Req 6 (secure development, patching) — via vulnerability
  management, SAST/SCA/SBOM and change controls.
- Req 8 (identification & authentication) — DIRECT via the MFA
  control; Req 10 (logging) via audit-logging signals; Req 11
  (testing) PARTIAL via scan coverage + ASV process evidence.
- Req 3/4 (stored/transmitted cardholder data) — only PARTIAL
  technical support (encryption signals); scope and segmentation
  evidence is manual.
- Req 9/12 are administrative/physical — manual evidence only.

PCI DSS compliance is assessed by a QSA/ASV against the
organization's cardholder data environment. DSRclone provides
evidence and gap tracking; **it is not a QSA and does not attest
PCI DSS compliance.**
