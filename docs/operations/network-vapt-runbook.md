# Network VAPT Runbook (Prompt 33)

Day-to-day operation of Network VAPT V2:

1. **Create a target** — the parent target must be VERIFIED with an
   APPROVED assessment; private ranges additionally need the recorded
   internal-engagement assertion. Loopback/metadata values are refused
   at creation, always.
2. **Preflight** — read the checks, not just the verdict. BLOCKED names
   the failed authorization fact; TOOL_UNAVAILABLE means the probe
   transport is not wired in this deployment (expected here).
3. **Plan** — review stages, tools, the exact NSE selection, blocked
   items and the budget notice before starting anything. A
   MASSCAN_NOT_APPROVED blocked item means one of the §27 gate inputs
   is missing — do not work around it; record the missing permission
   or platform record properly.
4. **Coverage** — after any run, read limitations first. PARTIAL /
   COMPLETED_WITH_GAPS means named hosts or scanners did not run;
   treat unscanned hosts as UNKNOWN, never clean.
5. **Drift** — baselines are versioned; compute drift after discovery
   runs and triage ELEVATED signals (new sensitive services on
   critical production assets) first.
6. **Packet captures** — requests are recorded with bounds; in this
   deployment the transport is NOT_CONFIGURED, so a REQUESTED job is a
   governance record, not a capture.
7. **Verification requests (Metasploit)** — decisions are policy
   records. APPROVED_FOR_MANUAL_CONTROLLED_RUN still executes nothing;
   it authorizes a human-controlled process outside this platform.
