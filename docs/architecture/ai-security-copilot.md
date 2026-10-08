# AI Security Copilot — architecture (Prompt 21)

The copilot is an **analyst assistant** over normalized platform data.
It explains, summarizes, drafts and proposes. It never executes:
no shell, no SQL, no scanner, no cloud/Kubernetes mutation, no
wireless attack (§7/§120). The pipeline for every task:

```
RBAC check (§11/§116)
  → tenant-filtered context load (§12)
  → SecurityContextBuilder (least-context, §9/§10)
  → prompt-injection scan (§20)
  → redaction (§15)
  → AITaskPolicy (§6): ALLOW / DENY / REQUIRE_REDACTION / REQUIRE_REVIEW
  → budget + rate gate (§104/§105)
  → AIProvider.generate (§3)  [primary → policy-checked fallback (§107)]
  → grounding + citations (§21/§22) → confidence (§26)
  → output sanitization (§79)
  → AiRequestLog (§63) + audit (§117)
```

## Components

- **SDK `packages/security-sdk/src/ai/`** — deterministic core:
  types/classification, redaction, injection detection, task policy,
  context builder, prompt assembly, grounding/confidence, provider
  abstraction (+ deterministic MOCK), NL query DSL, knowledge/vector
  search, output sanitization, budgets, golden evaluation fixtures.
- **API `apps/api/src/modules/ai-security/`** — `AiConfigService`
  (providers/models/policy/budgets), `AiContextService`
  (tenant-filtered loaders incl. immutable report snapshots),
  `AiCopilotService` (pipeline, finding tasks, scan/asset summaries,
  report drafting, workspace chat), `AiPlatformService` (NL search,
  knowledge, action proposals, feedback, dashboard/usage, evaluation).
- **AI service `apps/ai`** — model-facing prompt assembly + provider
  contract in Python (mirrors §19 separation), honest status endpoint.
- **Web** — `/ai` dashboard + NL search bar, `/ai/copilot` chat,
  `/settings/ai` admin, finding-detail AI panel (§111).

## Honest states

No provider configured ⇒ `NOT_CONFIGURED`: deterministic RULE_BASED
summaries are still offered and are **labelled rule-based**, never
presented as AI output. Only the in-process MOCK transport is
provisioned in this build; external/LOCAL provider rows report
NOT_CONFIGURED health rather than faking a probe (§103/§110). The
core platform (scanning, findings, retesting, reporting) has no
dependency on AI availability.

## Data model

`AiProviderConfig` (credential **reference** only), `AiModel`,
`AiWorkspacePolicy`, `AiUsageBudget`, `AiConversation`, `AiMessage`
(sanitized content only), `AiRequestLog` (counters, never prompts),
`AiCitation`, `AiSuggestedPatch` (review-only), `AiActionProposal`,
`AiFeedback`, `KnowledgeDocument`, `AiEmbedding`, `AiEvaluationRun`.
Migration `20261007180000_ai_copilot` (generated, not applied — the
standing no-Docker build-side gap; see Prompt 25/38 provisioning).
