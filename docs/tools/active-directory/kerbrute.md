# Kerbrute

**Posture:** DISABLED — offensive registration (Prompt 15)

Kerbrute performs username enumeration, password spraying and
AS-REP/TGS requests for offline cracking (§53). Credential attacks
are permanently excluded (§120): DISABLED registration only, no
adapter, never enabled. The posture engine instead FLAGS accounts
whose configuration would make such attacks possible (pre-auth not
required, stale privileged service accounts) from collected data —
observation, never execution (§58).
