# Remediation Ticket Redaction (Prompt 31 §41–§43)

External tickets are the leakiest surface in a remediation platform,
so payload construction is allowlist-based:

- Only safe fields are composed: severity, priority, a coarse asset
  reference (host/endpoint), CVE/CWE identifiers, the risk summary,
  a *safe* remediation summary, the due date and the DSRclone case
  reference.
- The composed title and body then pass secret-pattern scrubbing
  (cloud keys, tokens, private keys, connection strings); every
  redaction is counted on the payload so operators can see that
  scrubbing happened.
- Restricted evidence, exploit detail, credentials and raw scanner
  output are never copied into a ticket. Binary attachments are never
  sent.
- The payload that was built is stored on the work item, so what left
  the platform is auditable after the fact.
