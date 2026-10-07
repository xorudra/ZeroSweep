# Report Data Protection (Prompt 20 sections 63-70)

Report snapshots are sanitized and redacted ONCE at build time, so
no export format can leak what another hides: bearer tokens,
cookies, session values, passwords, API keys and PEM private-key
blocks are redacted from titles, descriptions and evidence
summaries. Exports carry evidence fingerprints (hashes) for
traceability instead of raw secret-bearing payloads.
Classification defaults to CONFIDENTIAL; every export carries the
classification watermark. Downloads require the DOWNLOAD_REPORT
permission and are written to the audit log with the artifact
checksum. Snapshot content hashes make tampering detectable - the
worker refuses to render a snapshot whose document does not hash
to its recorded value.
