# EASM Active Probing Policy

Active probing in EASM means *governed discovery probes only*:

| Probe | Allowed when | Bounds |
|---|---|---|
| DNS resolution | Root VERIFIED + active-authorized | Recorded transports only |
| TLS handshake | Same | Certificate facts only; no exploitation |
| HTTP probe | Same + policy `httpProbing` | One URL per host per run; redirects **recorded, never followed** into scope; parameter *names* only |
| Service discovery | Same + policy `serviceDiscovery` | Ports restricted to the approved `EasmServiceDiscoveryProfile` port set |

Never in EASM, under any authorization:

- vulnerability scanning, exploitation, credential attempts,
  directory brute force, takeover attempts, phishing/lookalike
  registration, or scanning of third-party/shared assets.

Those belong — if anywhere — to the platform's gated assessment
pipeline (VERIFIED target + APPROVED assessment), which EASM feeds
only through promotion of an UNVERIFIED asset.

Policy mode `PASSIVE_ONLY` forces `httpProbing` and
`serviceDiscovery` off even if a caller tries to enable them.
Payloads submitted for unauthorized active sources are dropped
before ingestion and counted in run coverage.
