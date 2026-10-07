# Active Directory Security Assessment (Prompt 15)

DSRclone's Active Directory capability is a **defensive posture
assessment** for authorized internal engagements. It inventories a
registered domain, builds an evidence-backed identity graph, computes
posture findings from the collected data, models attack paths as
analysis results, and tracks drift between snapshots. It never
performs an offensive action: no credential attacks, no exploitation,
no lateral movement, no directory modification — see
`docs/security/ad-offensive-tool-policy.md` for the enforced
exclusion list and `docs/security/ad-credential-model.md` for how
assessment identities are handled.

## Targets and registration

Domains register as verified targets (`ACTIVE_DIRECTORY_DOMAIN`,
`ACTIVE_DIRECTORY_FOREST`, `DOMAIN_CONTROLLER`, `LDAP_DIRECTORY`;
`ACTIVE_DIRECTORY` remains the legacy alias). Registration records
identity metadata only — DNS name, optional SID/functional level,
environment, criticality, the forest link, the credential profile
(reference name only) and the explicitly approved domain controllers.
Scans start only through the standard gated path (VERIFIED target +
APPROVED assessment + scope), exactly like every other target kind.

## Collection

Collection runs **only** on `DIRECTORY_ANALYSIS` workers (§10/§11) —
the stage executor denies directory adapters on any other worker,
and only explicitly approved domain controllers/hosts are ever
contacted. Sources, in preference order:

1. **Governed imports** — BloodHound/SharpHound datasets, PingCastle
   reports, Certipy `find` output, SmbMap/enum4linux-ng output and
   ADExplorer exports, all parsed by bounded, hostile-input-hardened
   parsers. Credential material found in an export is stripped
   recursively before persistence (§113).
2. **Platform connectors** — a read-only LDAP connector using typed,
   platform-generated queries only (LDAPS preferred; raw filters are
   refused in adapter configuration, §14) and a BloodHound collection
   connector whose collection methods are policy-classified
   (SAFE / REVIEW_REQUIRED / DISABLED, §29).
3. **Governed CLI adapters** — ldapsearch, SharpHound, PingCastle
   (healthcheck mode only), enum4linux-ng (bounded flags only),
   SmbMap (inventory flags only), Certipy posture (FIND action only).

Live transports are deliberately unwired in this build: registered
domains report `NOT_CONFIGURED` honestly until a deployment wires a
read-only transport inside an approved internal worker. Nothing is
ever fabricated.

## Pipeline

Profiles `AD_INVENTORY`, `AD_BASELINE`, `AD_COMPREHENSIVE`,
`ADCS_POSTURE`, `SMB_POSTURE`, `IDENTITY_GRAPH` and
`ATTACK_PATH_ANALYSIS` compose the stages (§86):
DOMAIN_DISCOVERY → DIRECTORY_INVENTORY → LDAP_POSTURE / SMB_POSTURE →
GRAPH_COLLECTION → PINGCASTLE_POSTURE → ADCS_POSTURE → NORMALIZATION
→ CORRELATION → ATTACK_PATH_ANALYSIS → RISK_ANALYSIS → REPORTING.
Posture findings carry canonical fingerprints
(`ad|<domain>|<rule>|<objectType>|<objectId>`) so native checks,
PingCastle and imports converge on one finding per issue (§61), and
they map onto the versioned `MS_AD_BASELINE` control catalog (§81) —
posture evidence, never a certification claim.

## Data sensitivity

Directory data is identity information. Inventory lists require
`VIEW_AD_IDENTITIES`; the raw graph requires
`VIEW_RAW_DIRECTORY_GRAPH` (OWNER/ADMIN) and every access is audited
(`DIRECTORY_ARTIFACT_ACCESSED`). Raw collector datasets are stored as
HIGH-sensitivity artifacts, never in findings or events. All state is
tenant-isolated by workspace.
