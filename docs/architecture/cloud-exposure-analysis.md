# Cloud Exposure Analysis (Prompt 14 §46–§48)

Exposure is classified from **configuration evidence only** — the
platform never probes the estate over the network to "check" whether
something is reachable.

## Exposure classes (§47)

| Class | Meaning |
|---|---|
| `PUBLIC` | The configuration itself proves internet reachability (public access flag, world-open rule on a sensitive service, public IP on an exposed resource) |
| `INTERNET_REACHABLE_POSSIBLE` | A public path exists but an intervening control may block it |
| `PRIVATE` | Configuration shows no public path |
| `UNKNOWN` | The inventory did not carry enough evidence |

## Network rules

- `firewall-sensitive-port-world` — ingress from `0.0.0.0/0` (or `*`)
  to a sensitive administration/database port (22, 3389, 3306, 5432,
  6379, 27017, …) is a finding.
- `firewall-world-open-port` — world-open ingress to other ports is
  recorded at lower severity; standard web ports (80/443) on web
  workloads are context, not findings.
- `serverless-public-access` — publicly invokable functions/apps.

Storage and database public access (`storage-public-access`,
`database-public-access`) feed the same exposure model, and public
findings carry `findingClass = PUBLIC_EXPOSURE`, which the quality
gate treats as a hard failure for critical storage (§70).

CloudMapper imports contribute AWS public-node evidence (§27) into the
same model. The GUI surface is `/cloud-security/exposure`, backed by
`GET /cloud/exposure`.
