# EASM Asset Ownership

Ownership is an evidence-backed resolution, not a discovery claim.

## Evidence weights (SDK `resolveOwnership`)

| Evidence | Weight | Notes |
|---|---|---|
| Manual approval (`EVIDENCE_APPROVED`) | 1.00 | Decisive |
| DNS challenge demonstrated | 0.95 | Root verification challenge |
| Cloud account match | 0.90 | |
| Organization certificate | 0.85 | Cert org == program org |
| Registrar match | 0.75 | |
| IP range match | 0.70 | |
| Shared-hosting signal | 0.40 | Pushes toward SHARED |
| Certificate SAN mention | 0.35 | Never sufficient alone |
| Root relationship | 0.35 | Under a program root domain |
| Brand similarity | 0.25 | Labelled observation |

Bands: decisive evidence or corroborating weight ≥ 0.90 from ≥2
independent kinds ⇒ `VERIFIED/HIGH`; ≥ 0.60 ⇒ `VERIFIED/MEDIUM`;
≥ 0.30 ⇒ `LIKELY/MEDIUM`; anything weaker ⇒ `UNKNOWN/LOW`.
Third-party-decisive rules dominate; shared-hosting evidence with no
ownership evidence resolves to `SHARED`.

## Rules

`AssetOwnershipRule` rows (per workspace) declare VERIFIED /
THIRD_PARTY / SHARED ownership for exact values or domain suffixes;
decisive rules win over heuristic resolution.

## Promotion bar (§70)

`canPromoteCandidate`: ownership `VERIFIED` (with `HIGH`/`MEDIUM`
confidence), or `LIKELY/HIGH`; never `THIRD_PARTY`, never
`UNKNOWN/LOW`, never for a `REJECTED` candidate. Promotion creates
canonical records but **never verifies the target and never changes
`activeTestingStatus`** — see `easm-authorization-boundary.md`.

## Root verification

A root becomes `VERIFIED` only by demonstrating control: the DNS TXT
(or file) challenge published by the platform, matched against a
recorded observation carrying the same challenge value, or a recorded
manual-approval reference. A claimed reference without a matching
observation is refused and the root stays `PENDING`.
