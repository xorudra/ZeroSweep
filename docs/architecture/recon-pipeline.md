# Recon Pipeline Architecture (Prompt 5)

How ZeroSweep turns an authorized target into a trustworthy asset inventory —
and the guarantees that keep reconnaissance from ever becoming unauthorized
scanning.

## Flow

```
Subdomain discovery          DNS stage              HTTP stage            Knowledge stages
(subfinder, amass,     →     dnsx            →      httpx          →      whatweb (fingerprint)
 assetfinder, findomain)     (in-scope hosts        (services,            gau + waybackurls (history)
                              + wildcard probe)      tech, redirects)     katana (scoped crawl)
        │                          │                       │                       │
        └────────── every stage: authorize → scope → policy → execute → parse → normalize → persist
```

Stages are the Phase 4 DAG stages (`PASSIVE_RECON`, `ASSET_DISCOVERY`,
`DNS_RESOLUTION`, `HTTP_DISCOVERY`, `TECHNOLOGY_DETECTION`, `CRAWLING`,
`ENDPOINT_DISCOVERY`). A stage may select **several** adapters; all of them
run, each with its own ToolExecution record, and the stage outcome aggregates
(all → COMPLETED, some → PARTIAL, none → the stage's failure strategy).

## The three scope checkpoints (§23)

1. **Before execution** — the worker re-evaluates authorization, scope and
   policy from trusted database state immediately before running an adapter
   (Phase 4 behaviour, unchanged). DNS is re-resolved and re-validated at
   execution time to defeat DNS-rebinding (§24).
2. **During discovery processing** — every discovered hostname/URL is
   canonicalized and verdict-stamped `IN_SCOPE` / `OUT_OF_SCOPE` by the
   ScopeMatcher. Private, loopback, link-local, CGNAT, ULA and metadata
   addresses are blocked for active use by default (§25).
3. **Before downstream execution** — stage inputs (host/URL lists for dnsx,
   httpx, whatweb, katana) are loaded from persisted inventory filtered to
   `IN_SCOPE` only, and are re-validated by the adapter + policy gates.

Discovered assets **never** expand the authorized scope. Out-of-scope
discoveries are stored with their verdict for visibility (§33/§43) and are
never handed to an active tool.

## Canonicalization & provenance (§17–§20)

Hostnames: lowercase, trailing dot stripped, IDN converted to punycode,
malformed values rejected — so `API.Example.com.`, `api.example.com` and the
punycode form are one asset. URLs: scheme/host lowercased, default ports
removed, fragments dropped, duplicate slashes collapsed; path case and query
preserved so semantically different endpoints never merge. Endpoint identity
is method + origin + path; query parameter **names** union across
observations (values are ephemeral).

Every entity keeps its provenance: an asset carries the list of tools that
reported it (`sources`), endpoints/technologies carry their source tool. The
`ReconResultAggregator` (security-sdk) merges multi-tool results with these
rules wherever a combined view is needed (worker persistence merges the same
way per execution).

## Data protection (§21–§22)

* Parameter names are inventoried; parameter **values** of sensitive
  parameters (token, password, session, key, …) are redacted before anything
  is logged, persisted or shown.
* URLs in logs/timeline/UI are the redacted forms. Raw tool output is stored
  unmodified ONLY as the execution artifact in object storage
  (`scans/<scanId>/executions/<executionId>/<slug>.<ext>` with checksum),
  because it belongs to an authorized target.
* No raw scanner output appears in the GUI.

## Budgets & safety limits (§27–§30)

`DiscoveryBudget` caps subdomains, resolved hosts, HTTP targets, historical
URLs, crawl URLs, total requests and duration per scan. Administrators set
hard ceilings; users/profiles may only lower them. Adapters additionally
plan conservative rate/concurrency (httpx 25 threads/50 rps, katana 10
concurrency/depth ≤ 3). Wildcard DNS is detected with a deterministic probe
label and flagged instead of minting fake subdomains; redirects out of scope
become references, not targets.

## Failure behaviour (§38, §55–§56)

Adapter outcomes classify as SUCCESS / PARTIAL / FAILED / TIMED_OUT /
CANCELLED (PARTIAL = output produced despite a non-zero exit, and it is
parsed and kept). One tool failing degrades its stage to PARTIAL when other
adapters delivered; a tool whose binary is absent is skipped at dispatch
(multi-adapter stages) or policy-denied as `TOOL_UNAVAILABLE`. Orchestration
never crashes because a recon tool is missing.

## Profiles (§40–§41)

* `PASSIVE_RECON` — subdomain discovery (4 sources) + DNS resolution of
  discovered in-scope hosts + historical URL discovery (gau/waybackurls).
  No HTTP probing, no crawling: it stays passive about the target itself.
* `WEB_BASELINE` — everything above plus httpx probing, WhatWeb
  fingerprinting and the conservative Katana crawl. No vulnerability
  scanning, no exploitation (later prompts).

## Honesty rules

Health is probed, never assumed (`Tools` UI and plan-time selection show
UNAVAILABLE for missing binaries and fall back to the clearly-labelled
simulation adapter). Recon produces inventory only — findings are always
empty from these adapters (§47), and the recon summary (§46) reports counts
of assets/services/endpoints/technologies, never vulnerability claims.
Shodan/Censys are catalogued as credential-required integrations (§50) and
are not queried by this pipeline.
