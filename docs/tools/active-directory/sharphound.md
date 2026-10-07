# SharpHound

**Posture:** DEFENSIVE — governed collection (Prompt 15)

SharpHound collection is governed by the collection-method policy
(§29). SAFE methods (membership, ACLs, trusts, containers, object
properties) run by default. REVIEW_REQUIRED methods (local groups,
sessions, logged-on, RDP, DCOM, PS-remote) run only with a recorded
approval flag in the scan configuration. Anything unclassified is
treated as DISABLED. Collection runs only on DIRECTORY_ANALYSIS
workers against approved domain controllers, under a job-scoped
credential lease (§12).
