# hcxtools / hcxpcapngtool (Prompt 19 §23)

**Role:** offline capture processing adapter (`hcxtools`, executable
`hcxpcapngtool`), over **approved** capture artifacts only.

The adapter passes the capture reference as the sole argument and parses
the tool's summary output (networks, handshakes/PMKID counters). The
hash-export modes (`-o`, `-E`, john/hashcat formats) are **not
expressible**: if a summary line arrives in a hash format it is counted
as authentication material (§67) and the material itself is discarded —
never stored, logged or returned.

Runs `NO_NETWORK` on `WIRELESS_PASSIVE_ANALYSIS` workers, in
`WIRELESS_PCAP_ANALYSIS` stages only.
