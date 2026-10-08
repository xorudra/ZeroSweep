# Remediation Campaigns (Prompt 31 §87–§92)

A campaign coordinates one push across many assets: one CVE, one
vulnerable dependency, one technology, one KEV listing. Scope keys
(cve, componentPurl, product, technology, kevOnly) are ANDed;
membership is collected from real canonical findings, ensuring a
remediation case for each.

Progress is **computed from live case states on every read** —
total, assigned, in-progress, fix-claimed, verification-pending,
verified, closed, overdue, exceptions and % verified — never stored
counters that can drift. Campaign creation is idempotent on a
caller-supplied key.

Patch campaigns (§91) group by product + affected/fixed versions via
the findings' component data and Prompt 30 Patch Intelligence. The
SBOM exposure view (§92) answers "where does this component live":
repositories, direct/transitive counts, container images and assets,
from recorded findings only.
