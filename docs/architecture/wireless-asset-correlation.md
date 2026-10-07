# Wireless Asset Correlation (Prompt 19 §50–§54)

## Identity

An access point's identity is its **BSSID within an environment** (§5) —
never the SSID, which is an attacker-controlled label (§92) that many
unrelated APs may share. Stations are identified only by their workspace
HMAC pseudonym (§9).

## Multi-sensor dedup (§54)

Observations of the same BSSID from several sensors merge onto ONE
canonical `WirelessAccessPoint` row (unique `[environmentId, bssid]`);
each observation is preserved in `WirelessObservation` with its sensor,
channel, signal and timestamp, so provenance is never lost in the merge.

## Network asset link (§50)

Where evidence supports it, an AP links to the network `Asset` inventory
(`networkAssetId`) — correlation links, never duplicates: a wired-side
asset and its wireless observation stay one asset with two evidence
trails. Observed APs never become targets and never expand scope (§94).

## Finding correlation (§53)

Wireless findings carry the canonical fingerprint
`sha256(environment | BSSID | rule | security mode | finding class)`, so
the same posture issue reported by Kismet, tshark and the platform posture
pass converges on one canonical finding with every observation preserved.
