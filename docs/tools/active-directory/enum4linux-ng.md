# enum4linux-ng

**Posture:** DEFENSIVE — bounded enumeration (Prompt 15)

A governed wrapper runs enum4linux-ng with bounded flags (users,
groups, shares, password policy, JSON output). The all-in-one mode
and RID cycling are deliberately NOT used and are refused if
requested. Output contributes SMB/LDAP inventory: shares, dialect
and signing posture, and directory counts — never credentials.
