# Software Composition Analysis (Prompt 12 §45–§58, §69–§79)

## Inventory (§45/§56/§57)

Components are identified **lockfile-first** from the snapshot's
manifests — package-lock / pnpm-lock / yarn.lock, Pipfile.lock /
poetry.lock / requirements.txt, pom.xml / build.gradle, Gemfile.lock,
go.mod / Cargo.lock, composer.lock — and merged with scanner
observations (OWASP Dependency-Check, Grype) by **Package URL**
identity (§46). No package is ever installed and no registry is ever
queried at analysis time: inventory is computed from repository data
alone. Each component records name, version, ecosystem, PURL, source
manifest, scope (DIRECT / TRANSITIVE / UNKNOWN), dependency scope
(RUNTIME / DEVELOPMENT / TEST / PROVIDED), license identifiers and
supplier when the manifest declares them.

## Vulnerability matching (§52/§58/§73/§74)

Matching runs **only against the governed local intelligence dataset**
(Prompt 11: CVE / CWE / CPE / EPSS / KEV records with checksum-verified
sync). The discipline is inherited, not re-invented:

- The same CVE + component reported by Dependency-Check and Grype
  merges into one finding with both provenances (§58).
- A CPE→CVE link means the component **may** be exposed:
  reachability is `POTENTIAL_EXPOSURE` (or `UNKNOWN`), never a
  confirmed vulnerability (§73). Reachability upgrades require
  dataflow evidence the platform actually holds.
- A fixed version is shown **only** when trusted data provides it
  (scanner fix state or the intelligence record) (§74).
- An empty dataset yields **zero** matches — the UI shows the inventory
  with no vulnerability claims rather than inventing any (§52).

## Baselines and retests (§77/§79)

Findings are classified against the previous snapshot of the same
repository by their line-stable / dependency fingerprints: `NEW`,
`EXISTING`, `RESOLVED`. Targeted source retests reuse the Prompt 11
retest runner with focused profiles (SAST_ONLY / SECRETS_ONLY /
DEPENDENCIES_ONLY); an incomplete retest scan judges INCONCLUSIVE,
never a pass.
