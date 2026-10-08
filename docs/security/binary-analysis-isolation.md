# Binary Analysis Isolation (Prompt 35 §12/§60/§67–§70)

- Binaries are untrusted input, parsed STATICALLY by safe parsers
  and governed adapters in isolated workers — never executed,
  loaded as code, or analyzed in the API/web process (§100 of
  Prompt 18; §164 of Prompt 35).
- Ghidra headless runs carry timeout, memory limit, disk quota and
  output limit (§60); overruns terminate the worker task and leave
  the analysis partial/error (§148) — never a hung platform.
- Debugging (GDB/pwndbg) exists only as governed LAB records:
  local authorized artifacts, isolated workers, timeouts and
  resource limits (§69), separation of duties between request and
  approval, transport NOT_PROVISIONED where no lab is wired.
- No automated exploit generation exists (§70): no ROP chains, no
  shellcode, no weaponized payloads, no persistence. Crash triage
  classifies and fingerprints; it never claims exploitability.
