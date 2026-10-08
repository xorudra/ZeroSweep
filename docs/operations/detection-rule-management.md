# Detection Rule Management (Prompt 28 operations)

## Lifecycle

`DRAFT → TESTING → ACTIVE`, with `DISABLED` / `DEPRECATED` exits.
Seed the built-in templates from `/soc/detections` — they arrive
as DRAFT rules with ATT&CK mappings and data-source requirements.

## Authoring

- Write definitions in the structured editor (JSON). The DSL
  compiler validates on save: unknown fields, code-shaped content
  and over-complex rules are rejected with specific errors.
- Prefer narrow conditions + threshold/sequence structure over
  broad single-event matches; every rule names its data source.

## Testing (§109/§110)

Test before promotion, with positive fixtures (should match),
negative fixtures (benign lookalikes that must not match) and, for
threshold rules, below/at-threshold counts. Testing evaluates the
stored definition against supplied events only — it creates no
matches, alerts or state.

## Promotion (§111)

Activation re-compiles the stored version; what activates is what
was tested. Editing an ACTIVE rule creates a new version and
returns it to TESTING — there is no silent in-place change to a
live detection.

## Tuning

- Watch the false-positive rate (from triage rows) and detection
  health. High FP is a tuning signal, never an auto-disable.
- Use scoped, expiring suppressions for known maintenance noise —
  include a reason; the suppression and its expiry are auditable.
- Deprecate rules whose data source is gone; health flags them as
  no-data-source until you do.
