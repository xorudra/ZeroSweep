# Reporting Engine (Prompt 20 sections 55-70)

Fifteen report types render from one immutable `ReportSnapshot`:
the snapshot document is built once from stored findings (bounded,
domain-filtered), redacted at build time, and content-hashed.
Exports (PDF/HTML/JSON/CSV) render from the snapshot - never from
live tables - by the worker's report runner into object storage
with SHA-256 checksums. Reports default to CONFIDENTIAL with a
watermark; approval flows DRAFT -> REVIEW -> APPROVED -> ISSUED,
and an ISSUED report can never be regenerated in place. Downloads
are permission-checked and audited. Schedules are stored
definitions; execution belongs to the Prompt 22 scheduler. Empty
scopes produce honest empty reports, never placeholder numbers.
