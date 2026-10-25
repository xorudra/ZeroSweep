# Web Attack-Surface, Content, Route & Parameter Discovery (Prompt 6)

How ZeroSweep discovers the parts of a web application that crawling and
historical sources miss — unlinked routes, files, directories and parameter
names — without ever turning discovery into exploitation.

## Pipeline position

```
HTTP_DISCOVERY → TECHNOLOGY_DETECTION → CRAWLING → CONTENT_DISCOVERY →
ENDPOINT_DISCOVERY → PARAMETER_DISCOVERY → WEB_SURFACE_NORMALIZATION → …
```

- `CONTENT_DISCOVERY` (capability `CONTENT_DISCOVERY`): ffuf, Feroxbuster,
  Gobuster, Wfuzz (CONTENT template). `WEB_BASELINE` bounds it to ONE
  adapter + SMALL wordlists; broader profiles run the full set at STANDARD.
- `PARAMETER_DISCOVERY` (capability `PARAMETER_DISCOVERY`): Arjun + Wfuzz
  (PARAMETER template), fed only prioritized in-scope endpoints.
- `WEB_SURFACE_NORMALIZATION`: a platform stage (no tool) marking the merge
  of crawl + archive + content + parameter results into one canonical
  inventory — the merge itself happens continuously in the worker's result
  processor and in the SDK's `WebSurfaceAggregator`.

All five adapters implement the same `SecurityToolAdapter` contract through
the Phase 5 `ReconAdapterBase` — there is no parallel execution framework.

## Governed wordlists (§10–§13)

Wordlists are platform data, not user input. `WordlistManager`
(security-sdk) holds the registry: bundled starter lists ship in the worker
image's controlled storage (`/wordlists/builtin/…`), each with a SHA-256
checksum over its entries; administrators register additional lists as
metadata + controlled-storage references (the `Wordlist` table). A scan
references a list **by id or by profile only** — id validation is
slug-shaped, so `/etc/passwd`, `../x` and friends are rejected before any
plan exists, and no API accepts a wordlist path at all.

Profiles: SMALL (baseline scans), STANDARD (comprehensive scans),
COMPREHENSIVE (explicit selection only — templates never auto-select it).
Selection falls downward when a category lacks the requested level, never
upward. Technology detections from earlier stages act as HINTS that add
technology-specific lists (e.g. WordPress routes) as additional references.

## Guardrails (§14–§15, §46–§47)

- `DiscoveryBudget` gained content ceilings: `maxContentRequests` (5k
  default / 50k admin cap), `maxDirectories`, `maxFiles`,
  `maxRecursionDepth` (3/6), `maxParameterRequests`, `maxVhostRequests`,
  `maxWordlistEntries`. Administrators set caps; users can only lower.
- Rates are conservative by default (10 rps) with per-adapter hard caps
  enforced in code (rate ≤ 50, threads ≤ 20, Feroxbuster depth ≤ 4).
- Crawler-trap detection drops loop-shaped URLs (repeated segments,
  extreme depth, absurd pagination, high-entropy session segments) before
  they become inventory; volatile query VALUES never create new endpoints
  (identity = method + origin + path + parameter names).

## Truthful inventory (§16–§23, §41–§45)

- Responses are classified from safe metadata only (status, length,
  content type, title, redirect target). Bodies are never stored.
- `Soft404Detector` calibrates from recorded baseline observations of
  certainly-nonexistent paths and flags fingerprint matches;
  `detectWildcardGroups` collapses ≥3 distinct paths sharing one success
  fingerprint into a single representative marked as wildcard behaviour.
  Both run in the SDK aggregator; the worker's per-execution processor
  applies the wildcard collapse + trap guards, and calibrated soft-404
  filtering applies where baselines are known (aggregation time).
- Redirects are RECORDED, never followed — an out-of-scope destination is
  an inventory reference, full stop.
- Sensitive files (`.env`, backups, configs) are recorded with MINIMAL
  metadata; their contents are never fetched by discovery tooling.
- Classification is not accusation: `/api/…` routes are typed `API`,
  admin-style routes are labelled `SENSITIVE_ROUTE` for prioritization —
  neither is a vulnerability, and this phase emits ZERO findings by design.

## Parameters & forms (§27–§35)

Parameters are first-class inventory (`EndpointParameter`): name, location
(QUERY/PATH/HEADER/COOKIE/BODY), provenance with unioned sources across
tools, confidence. NAMES only — values are never persisted anywhere.
Credential material is referenced (Credential / SessionProfile records from
earlier phases), never embedded in endpoints, plans or results. Forms are
recorded as structure metadata (action endpoint, method, field names,
encoding) for later safe-testing phases; nothing auto-submits a form, and
destructive forms are never submitted by automation.

## Outputs

- Inventory: `Endpoint` rows enriched with contentType/contentLength/
  title/redirectLocation/endpointType/classification/sources, plus
  `EndpointParameter` and `EndpointForm` rows.
- API (§55): `GET /endpoints`, `GET /endpoints/:id`,
  `GET /endpoints/:id/parameters`, `GET /assets/:id/web-surface`,
  `GET /scans/:id/web-surface`, `GET /scans/:id/endpoints` — all paginated
  where list-shaped and tenant-isolated.
- GUI: `/web-surface` overview, enriched Endpoints table, endpoint detail,
  asset + scan web-surface panels, and the new stages in the Live Scan DAG.

## Verification stance

No discovery tool was executed against any real target during development:
adapters are verified against recorded fixture output of a controlled test
application (example.com), plan-construction tests, and guardrail/scope
denial tests. On hosts without the binaries, health reports UNAVAILABLE
and orchestration degrades (a failed content tool makes its stage PARTIAL,
never silently successful).
