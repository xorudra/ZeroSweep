# Non-Production Environment Safety (Prompt 40 §250–§252)

A restored or staging environment must never act on the real world:

- Restored environments must NOT process live billing webhooks
  (provider endpoints/keys are environment-scoped; the restored copy
  carries no production webhook secret).
- Restored environments must NOT email real customers (mail transport
  is environment configuration; non-production uses a null/log
  transport).
- Restored product data (plans, usage, licenses) is inert history —
  license private keys are never in backups (§248), so a restore can
  never sign licenses.
- Test providers refuse to activate when NODE_ENV=production (§22);
  symmetrically, production providers must not be configured in
  non-production environments.
