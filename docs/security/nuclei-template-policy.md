# Nuclei template policy

Nuclei's power is its template library — which includes checks that
probe for SQL injection, reflected XSS, SSRF callbacks, default
credentials and denial-of-service conditions. ZeroSweep's automated
platform must be able to prove those checks **cannot run** in an
automated scan. This policy is enforced in code, in three layers.

## Classifications

| Class | Meaning | Automated scans |
| --- | --- | --- |
| `SAFE` | Passive/read-only checks: headers, cookie flags, TLS properties, exposed-file presence, tech version disclosure | ✅ selected |
| `REVIEW_REQUIRED` | Checks an admin may approve per program (e.g. CORS, open redirect, TRACE method) | ✅ only when explicitly approved for the profile |
| `INTRUSIVE` | Active injection/exploitation probes (SQLi, XSS, SSRF/OAST, SSTI, file inclusion…) | ❌ never |
| `DISABLED` | Credential attacks, default-login checks, fuzzing/DoS-class templates | ❌ never |

Tag/name heuristics classify uncurated templates conservatively:
anything smelling of credentials, brute force, fuzzing or DoS →
DISABLED; injection/XSS/SSRF families → INTRUSIVE; everything unknown →
REVIEW_REQUIRED (never SAFE by default).

## The three enforcement layers

1. **Selection** — `selectTemplates()` returns only SAFE + approved
   REVIEW_REQUIRED ids, capped by `maxNucleiTemplates`. INTRUSIVE and
   DISABLED ids are rejected with reasons even if a caller "approves"
   them (covered by unit tests).
2. **Invocation** — the adapter's execution plan points Nuclei at the
   governed collection directory and passes every non-selected catalog
   id via `-exclude-templates`. OAST is disabled (`-no-interactsh`).
3. **Normalization** — the adapter drops any finding whose template id
   is not automatable under the run's approvals and counts the exclusion
   in execution metrics (`policyExcludedTemplates`). A stale or tampered
   binary cannot smuggle intrusive results into the platform.

## Snapshots

Each scan records the template collection snapshot (name, version,
date) and the exact selected template ids in the execution metrics, so
any finding can be traced to the precise template set that produced it.
Template updates arrive as reviewed collection releases — never as
runtime downloads or user uploads.

## Custom templates (§48)

There is **no template upload feature** and no API accepts a template
path. Supporting customer templates later means: administrator-only
submission, mandatory review + classification through this same policy,
version-controlled storage, and inclusion in the snapshot — designed
here, intentionally not built as an upload box.
