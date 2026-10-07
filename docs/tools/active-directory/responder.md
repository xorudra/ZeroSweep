# Responder

**Posture:** DISABLED — offensive registration (Prompt 15)

Responder poisons LLMNR/NBT-NS/mDNS and captures credentials
(§54). Poisoning and credential capture are permanently excluded
(§120): DISABLED registration only, no adapter exists. The platform
detects the CONDITIONS that make poisoning viable (SMB1 enabled,
signing not required, weak LDAP channel binding) from collected
posture data instead.
