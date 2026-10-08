# Web Endpoint Inventory (Prompt 32 §23–§34)

## Canonical identity (§29)

An endpoint's identity is `scheme://host[:port] + METHOD + normalized
path`. Normalization replaces UUIDs, long hex strings and numeric
segments with `{uuid}`/`{hex}`/`{id}` templates and **excludes volatile
parameter values** — `/users/42?tab=a` and `/users/99?tab=b` are the
same endpoint. Observations are preserved in the canonical pipeline's
endpoint/provenance records (§25).

## Multi-tool merge (§24)

ffuf, Feroxbuster and Gobuster observations of the same path merge
into ONE canonical endpoint (via the shared `ContentDiscoveryAdapter`
abstraction, §20) carrying every contributing source and its status
observations — duplicate endpoints from overlapping tools are a bug,
not a feature (§189 test scenario).

## Bounded discovery (§21/§22/§26)

Wordlists are governed platform wordlists (no filesystem paths in
plans); entry counts, request totals, rate, threads and extensions are
clamped. Crawls are bounded by depth (≤5), URL count (≤10,000),
allowed domains (the scope snapshot), redirect limits and page size.

## Dangerous paths (§27)

Paths matching delete/destroy/remove/logout/signout/payment/purchase/
checkout/submit-order/admin patterns are **excluded from automatic
interaction** — they may be recorded as inventory when a passive source
reports them, but no automated request is issued against them.

## Historical URLs (§34)

Wayback/Gau-style historical URLs are candidates: they may be checked
against current scope, but are never automatically requested just
because they exist in an archive.
