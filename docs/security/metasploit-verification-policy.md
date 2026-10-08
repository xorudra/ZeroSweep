# Metasploit Verification Policy (Prompt 33 §75–§82)

No Metasploit adapter or transport exists in this platform. V2 ships
the policy layer, with the transport honestly **NOT_PROVISIONED**:
verification requests are evaluated, recorded with a full audit
trail, and never executed by an automated path.

A request is approvable only when ALL of §77 holds:

- explicit authorization covering the exact host;
- a specific target AND a specific finding (no fishing expeditions);
- a module from the reviewed allowlist (check-style scanners only:
  version probes and condition checks such as the MS17-010 and
  Heartbleed CHECK modules);
- the separate RUN_CONTROLLED_METASPLOIT_VERIFICATION permission;
- the host inside the frozen scope snapshot (else BLOCKED, §150).

Structurally forbidden (§79–§81) — rejected by policy construction,
independent of role or approval: reverse/bind shells, Meterpreter
sessions, any payload delivery, persistence, credential dumping,
lateral movement, privilege escalation, and any post-exploitation.
No persistent interactive sessions exist.

Safe verification is always preferred (§82) and is listed on every
verdict: version/configuration recheck, governed scanner confirmation,
and the VULN_APPROVED NSE check set cover the overwhelming majority of
fix-verification needs without any exploitation tooling.
