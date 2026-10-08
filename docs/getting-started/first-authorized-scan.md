# First Authorized Scan (Prompt 40 §154)

DSRclone tests **only** what you own or are explicitly authorized to
test (§168):

1. Complete the onboarding **Security Scope** step — the authorization
   attestation is required before active testing (§70).
2. Add a target and **verify ownership/control** (DNS/file/manual
   approval flows).
3. Define a **scope** for the target; discovered assets never expand
   scope automatically.
4. Create an assessment with the default **SAFE_STANDARD** profile
   (§71) and approve it.
5. Start the scan. The platform re-checks verification, approval,
   scope, policy, entitlements and quota at scan start (§12/§52) —
   every time, not just in the UI.
