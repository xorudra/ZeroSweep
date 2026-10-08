# EASM Technology Intelligence

- Technology names are normalized to a canonical form
  (`normalizeTechnologyName`: lowercase, separator-stripped) so
  `Node.js`, `NodeJS`, and `node js` are one technology.
- **Confidence counts independent sources only** — the resolver
  dedupes by evidence source before counting: 1 source ⇒ LOW,
  2 ⇒ MEDIUM, 3+ ⇒ HIGH.
- **Versions**: a version is asserted only when a source provided
  one and sources do not conflict. Family-only evidence
  (`familyOnly: true`) yields `version: null` — the platform never
  guesses a version from a product family. Conflicting version
  claims also resolve to `null` with the conflict recorded.
- Technology observations are **not vulnerabilities**. KEV/EOL/CVE
  correlation happens through linked findings on promoted assets via
  the unified vulnerability intelligence (P11); the technologies
  endpoint reports the join honestly (empty when nothing is linked).
