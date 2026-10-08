# Software Component Identity (Prompt 30 §28–§33)

- A **SoftwareProduct** (vendor + product + ecosystem + a canonical `productKey`) is the identity vulnerabilities attach to; **SoftwareVersion** rows carry per-version metadata.
- Identifiers: PURL is preferred (§29). CPE is used for OS/infrastructure products. `SoftwareIdentifierMapping` asserts PURL↔CPE equivalence for the same product with a source and confidence — mappings are evidence, not guesses: the same component under different identifiers across SBOMs merges by identity (§31), never by name alone.
- PURL handling (`identity.ts`): type lowercased, namespace/name rules per ecosystem (PyPI separator folding), percent-decoding of namespaces — `pkg:npm/@angular/core` and `pkg:npm/%40angular/core` normalize to one identity (§137).
- CPE validation (§138, §127): control characters, whitespace smuggling, wildcards in identity positions and over-length strings are rejected at ingestion; malformed identifiers are recorded as rejected records, never silently repaired.
- Identity resolution confidence ladder: PURL exact → EXACT; CPE vendor/product → HIGH; ecosystem+name+version → MEDIUM; name-only → LOW (never sufficient for a confirmed match).
