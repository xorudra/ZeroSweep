# Kismet (Prompt 19 §16–§18)

**Role:** passive wireless discovery adapter (`kismet`), category
WIRELESS, worker type `WIRELESS_PASSIVE_ANALYSIS`.

Kismet **listens only**: the adapter composes a fixed argument set
(`-c <approved-interface>:type=linuxwifi --no-ncurses --silent`) from the
store-resolved sensor record. It never associates, probes, transmits or
changes interface state beyond the approved sensor configuration, and no
client-supplied source, channel list or option can reach the command
line (§78/§91).

**Output:** the Kismet device JSON is parsed with an allowlist of fields
(§18) — identity (BSSID), sanitized SSID, channel/frequency, security
metadata, signal, stations (pseudonymized at parse, §9). Credential-shaped
fields in a device record are never read.

**Honest state:** without sensor hardware the binary is absent and
health reports UNAVAILABLE; an administrator-managed Kismet *instance*
connector exists as a registration and reports NOT_CONFIGURED (transport
unwired) rather than fabricating a feed.
