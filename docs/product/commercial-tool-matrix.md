# Commercial Tool Matrix (Prompt 40 §288/§122–§126)

Source of truth at runtime: `GET /product/commercial-tools`, computed
from the tool registry. Rules:

- ZeroSweep **never bundles or redistributes commercial licenses**
  (§123). Commercial tools are customer-supplied (§124): the customer
  installs and licenses the tool; ZeroSweep connects via its governed
  adapter.
- Credential handling for commercial tools uses secret references only
  (§125) — never plaintext in plan/license/usage data.
- Each tool reports one of: NOT_CONFIGURED, LICENSE_REQUIRED,
  CONFIGURED, UNAVAILABLE, ERROR (§122). An unconfigured commercial
  tool degrades only its own capabilities (§126) — open-source
  alternatives continue to work.

| Tool | License model | Status source |
|---|---|---|
| Burp Suite Professional | ADMIN_PROVIDED | registry `licenseType` + configuration |
| Acunetix | ADMIN_PROVIDED | registry `licenseType` + configuration |
| Nessus | ADMIN_PROVIDED | registry `licenseType` + configuration |
| Qualys | ADMIN_PROVIDED | registry `licenseType` + configuration |

The live per-deployment list (including every catalog tool) is
generated at `docs/tools/index.md` from the registry (§157).
