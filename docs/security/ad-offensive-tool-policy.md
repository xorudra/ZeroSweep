# AD Offensive-Tool Policy (Prompt 15 §51–§56, §112, §120)

ZeroSweep's AD capability is defensive. The following are **never**
implemented, at any tier, behind any flag:

- Password spraying, brute force or credential guessing of any kind
- Kerberoasting / AS-REP roasting execution (requesting tickets or
  hashes for cracking), hash extraction or dumping (LSASS, NTDS,
  secretsdump-class tooling), pass-the-hash / pass-the-ticket
- Golden/Silver ticket forgery, DCSync, DCShadow
- NTLM relay, LLMNR/NBT-NS/mDNS poisoning, credential capture
- Remote code execution, lateral movement, persistence, privilege
  escalation execution
- AD CS exploitation (ESC abuse, certificate theft/forgery)
- Any modification of a directory object

## Enforcement, in code

1. **Registrations, not adapters.** NetExec, Impacket, Kerbrute,
   Responder, PowerView and offensive Certipy exist only as
   `AD_DISABLED_REGISTRATIONS` descriptors (status DISABLED). No
   adapter class exists for them; they are absent from
   `EXECUTABLE_SLUGS`, from every stage's allowlist and from the seed's
   implemented set — so no profile can select them, and tests assert
   exactly that (§112).
2. **Split tools are split in code.** Certipy is two things: the
   governed `certipy-posture` adapter (FIND action only; every other
   action refused at plan time) and the DISABLED offensive
   registration. BloodHound collection methods are policy-classified;
   SharpHound configurations naming a non-SAFE method are refused
   unless a recorded approval covers the REVIEW_REQUIRED set.
3. **Requests are refused loudly.** An API scan request naming an
   offensive slug is rejected with 400 and audited
   (`AD_OFFENSIVE_ACTION_BLOCKED`, §117) — the attempt is a security
   event, not a silent ignore.
4. **SPN presence is inventory, not a finding** (§58): service
   accounts with SPNs raise a finding only with compounding factors.
   Observing that an account *could* be Kerberoasted is posture;
   requesting its ticket would be an attack, and the platform does
   not do it.
