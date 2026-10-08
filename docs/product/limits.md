# Product Limits (Prompt 40 §276/§277)

Limits are enforced by the Quota service from real rows (§44/§45).
Values below are the EXAMPLE plan definitions (§256); a deployment's
actual limits come from its own plan versions, policies and platform
overrides (§15 precedence: safety ceiling → deployment → license →
plan → override).

| Dimension | Community | Trial | SaaS Starter | SaaS Pro | Enterprise | Self-Hosted |
|---|---|---|---|---|---|---|
| USERS | 3 | 5 | 10 | 50 | unlimited* | unlimited* |
| WORKSPACES | 1 | 3 | 5 | 25 | unlimited* | unlimited* |
| ASSETS | 25 | 250 | 500 | 5,000 | 50,000 | unlimited* |
| CONCURRENT_SCANS | 1 | 2 | 3 | 10 | 25 | 10 |
| MONTHLY_SCANS | 20 | 200 | 500 | 5,000 | 25,000 | unlimited* |
| REPORTS (monthly) | 10 | 100 | 250 | 2,500 | 10,000 | unlimited* |
| AI_REQUESTS (monthly) | 0 | 200 | 0 | 5,000 | 25,000 | 1,000 |
| INTEGRATIONS | 0 | 5 | 3 | 25 | unlimited* | unlimited* |
| CLIENT_USERS | 0 | 10 | 10 | 100 | 500 | 100 |

\* "unlimited" means no plan limit is set; **fair-use and hard safety
ceilings still apply on every tier** (§53): max targets per scan 100,
max requests/second per scan 50, max findings per scan 10,000, max
assets per organization 100,000, max concurrent scans per
organization 50, max report size 100 MB. Ceilings are platform safety,
not plan features, and quota can never widen authorization scope
(§52).

Over-limit behavior (§118): existing data stays readable and
exportable; creation beyond the limit is blocked with a structured
QUOTA_EXCEEDED response.
