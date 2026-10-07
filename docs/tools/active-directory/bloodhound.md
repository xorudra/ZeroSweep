# BloodHound

**Posture:** DEFENSIVE — import + graph analysis (Prompt 15)

BloodHound datasets (SharpHound JSON exports) are imported through
the bloodhound-connector and parsed into the evidence-backed identity
graph (§28/§32): users, groups, computers, OUs, GPOs, trusts, ACE
edges and membership edges, each with source + confidence provenance.
Session and local-admin edges follow the collection policy (§29) —
they are dropped at parse time unless approved, and the drop is
counted. Credential-shaped fields in an export are stripped
recursively before persistence (§113). The graph feeds posture
analysis and defensive attack-path modeling; nothing is executed
against a live directory by this tool.
