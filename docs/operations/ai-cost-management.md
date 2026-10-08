# AI cost management (Prompt 36 §121–§124)

- Budgets: per-workspace monthly token limit + per-task limit
  (AiUsageBudget). The copilot pipeline refuses work beyond budget
  with AI_BUDGET_EXCEEDED; the planner validates estimated plan cost
  against remaining budget (§46).
- Routing prefers cheaper/faster model classes when the task allows
  (costClass/latencyClass are hard ceilings, not hints — §5).
- Observability: request counts, token totals, approval rate,
  validation-failure and insufficient-evidence rates on the
  /ai-security dashboard. Cost is reported ONLY from provider
  metadata; absent metadata ⇒ null, never an invented estimate.
- Waste signals: repeated identical tool calls (loop detector),
  high INSUFFICIENT_EVIDENCE rate (retrieval/context problem, not a
  model problem), and per-task token outliers in traces.
