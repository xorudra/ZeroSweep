# Network Scanner Health (Prompt 33 §120)

Tool health for the V2 network set (Nmap, Naabu, RustScan, Masscan,
OpenVAS, Nessus, tshark, tcpdump, Metasploit-if-enabled) is served at
`GET /api/v1/vapt/network/tool-health` and shown on the Network VAPT
dashboard. States are honest:

- Registry-backed tools report their catalog state (enabled /
  healthStatus); absent a registry record the state is NOT_CONFIGURED.
- Execution mode in this deployment is FIXTURE_ONLY for every network
  tool: recorded outputs drive verification; no live worker transport
  is wired.
- Metasploit reports NOT_PROVISIONED by design (policy layer only).
- Masscan additionally requires the HIGH_THROUGHPUT worker capability;
  L2 tools (Netdiscover, arp-scan) require L2_LOCAL_NETWORK; tcpdump
  requires PACKET_CAPTURE. Capabilities are advertised by workers,
  never assumed by the API.

A tool reporting unavailable does not fail a plan outright — it
becomes a coverage limitation at run time, and a vulnerability scanner
being down makes the outcome PARTIAL, never clean (§155).
