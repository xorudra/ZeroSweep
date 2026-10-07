# NetExec

**Posture:** DISABLED — offensive registration (Prompt 15)

NetExec performs offensive remote operations and credential
attacks (§51). It is a DISABLED registration only: no adapter
exists, it is never enabled, no stage can select it, and requests
naming it are refused and audited (AD_OFFENSIVE_ACTION_BLOCKED).
Defensive SMB/LDAP inventory is provided by the governed smbmap and
enum4linux-ng adapters instead.
