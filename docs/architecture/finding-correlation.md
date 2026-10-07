# Finding Correlation (Prompt 11 §62–§64 — extends Prompt 7 §19–§21)

Canonical identity is stable across scans: workspace + asset +
service/endpoint + vulnerability class + CVE/CWE + canonical
fingerprint. Correlation never creates a second canonical finding for
the same issue:

- same canonical fingerprint → same Finding row; the new detection is
  recorded as a `FindingObservation` (source tool, source fingerprint,
  observed severity, timestamp) and the finding's `sources` union grows;
- the same CVE on a DIFFERENT asset stays a separate instance (§95);
- scanner conflicts (different severities for one issue) are preserved
  on the observations; the canonical keeps Risk Engine V2's effective
  values (§63);
- duplicates are re-homed (`duplicateOfId`), never deleted — evidence is
  preserved (§20);
- `firstSeen`/`lastSeen`, `resolvedAt`/`reopenedAt` and
  `recurrenceCount` give the cross-scan history §60 requires.

Report imports (Nessus/Greenbone) flow through the same correlation, so
an imported issue that a live scan also finds corroborates instead of
duplicating.
