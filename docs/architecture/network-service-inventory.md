# Network Service Inventory (Prompt 33 §26–§42)

Port discovery coordinates Naabu (bounded), RustScan (controlled fast
discovery, candidates confirmed by service identification), Nmap
(service/version detection) and Masscan (gated — see
network-tool-safety). Port sets are bounded: COMMON, WEB,
INFRASTRUCTURE, DATABASE, CUSTOM_APPROVED (≤1000 ports). FULL_TCP
materializes only with an explicit policy grant; it is never a
default and never auto-derived.

Service observations record IP, port, transport, state (OPEN / CLOSED /
FILTERED / OPEN_FILTERED / UNKNOWN), service, product, version,
confidence and source. Version claims preserve confidence: ambiguous
evidence stays a hint — a weak banner never becomes a confirmed
product/version, and never a confirmed CVE.

OS fingerprinting produces `OsFingerprintObservation` rows with
family, version hint, confidence band and source. Weak fingerprints
remain LOW-band hints; nothing downstream promotes them to facts.

Protocol analysis is performed over already-collected evidence only:
SSH algorithms/version, FTP anonymous posture (profile-gated check,
no platform login), SMB dialect/signing, LDAP TLS posture, RDP NLA
evidence, DNS zone transfer (separately authorized), database exposure.
No authentication attacks of any kind exist in this layer.
