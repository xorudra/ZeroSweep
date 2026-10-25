# Pacu — DISABLED (Prompt 14 §34/§89)

## Status: DISABLED, by policy, permanently for this platform

Pacu is an AWS **exploitation** framework. ZeroSweep performs
read-only assessment only (§7), so Pacu is registered in the tool
catalog as a governed descriptor and **nothing more**:

- Classification: `CLOUD_OFFENSIVE_TESTING`
- Risk level: `INTRUSIVE` / HIGH
- `enabled`: **false** — the seed never enables it
- **No adapter class exists.** There is no code path that can build an
  execution plan for Pacu, no stage in any profile can select it, and
  it is absent from the executable slug set (`CLOUD_SEC_SLUGS`).
- Its health surface is a governed **DISABLED constant** — never a
  probe, never derived from configuration.

The catalog entry exists so the Tools GUI can show the governed state
and policy can name the tool. Enabling Pacu would require a different
product decision — offensive testing is out of scope for ZeroSweep's
assessment platform, and this document is the record of that line.
