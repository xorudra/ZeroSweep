# Pricing & Billing Model (Prompt 40 §256–§259)

- The repository ships **example plan definitions only** (§256). No
  commercial prices are invented anywhere in code, seed data or docs
  (§257). Prices, when an operator commercializes a deployment, are
  separate business configuration — not source code.
- Currency is never hardcoded (§258); invoice references carry the
  provider's currency.
- There is **no custom tax engine** (§259). Tax calculation, where
  required, belongs to the billing provider of record.
- Billing is provider-abstracted (§19/§20): without a configured
  provider the deployment reports NOT_CONFIGURED and never simulates a
  payment (§21). The built-in TEST provider exists for integration
  testing and is refused in production (§22).
- Webhooks are signature-verified, replay-windowed and idempotent
  (§23/§24). Billing events store safe metadata only; card data is
  refused at the boundary (§26).
