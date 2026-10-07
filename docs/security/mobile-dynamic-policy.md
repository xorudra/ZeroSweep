# Mobile Dynamic Analysis Policy (Prompt 17 §69–§75/§119)

## Default posture

Dynamic instrumentation is **off by default**. Static profiles
never enable it. Frida's registration is DISABLED for normal
profiles; Objection's is APPROVAL_REQUIRED.

## MobileInstrumentationPolicy

Instrumentation runs only through **administrator-reviewed,
versioned modules**. A module record carries: module, version,
hash, capability, risk classification, approval state. The policy
evaluator refuses a session when any of these fail:

- a requested action is on the prohibited list (§75);
- a script body or shell command is present in the request
  (arbitrary code entry points do not exist);
- a requested module is unknown, unapproved or revoked;
- there is no approved session context (authorized build + lab
  device + approved profile);
- instrumentation approval is missing;
- a kill switch is active (Prompt 16, six levels);
- budget bounds (duration, module count) would be exceeded.

Every refusal is recorded: the session is stored BLOCKED with
reasons and `MOBILE_DYNAMIC_ACTION_BLOCKED` is audited (§116).

## Never implemented (§75/§119)

Credential theft, session-token theft, account takeover, payment
manipulation or abuse, device persistence, spyware behavior, SMS
interception, contact extraction, personal file extraction,
security-control bypass against third-party applications, arbitrary
ADB shell, arbitrary Frida scripts, arbitrary Objection commands.
There is no automated root/jailbreak bypass and no automated
certificate-pinning bypass in any profile (§23/§71).

## Lab-only

Instrumentation targets only the authorized build, on a
DSRclone-managed lab device, inside an approved session, with a
timeout and a recorded cleanup/reset (§57/§73).
