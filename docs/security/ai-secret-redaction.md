# AI secret redaction (Prompt 21 §15–§17, §93)

## Redaction engine (§15)

`AIRedactionEngine` reuses the platform's evidence redaction
(`redactEvidenceText`, Prompts 8/16/20: bearer tokens, cookies,
passwords, API keys, basic-auth URLs) and adds AI-payload patterns:
private keys, AWS access keys, Wi-Fi PSKs, session/JWT tokens. It
returns the sanitized text plus a redaction count, which is written
to the request log and audited (`AI_CONTEXT_REDACTED`) whenever > 0.

## Field-level rules

- Evidence and observation text: always redacted before inclusion.
- SECRET-classified fields: **removed** from context entirely, never
  masked-and-sent (`redactClassifiedFields`).
- Structured credential material is never a context field: the
  platform stores credential *references* only, so there is no secret
  value anywhere in the normalized model to leak.

## Access policies (§16/§17)

- Source code: `REDACTED` by default (workspace policy may set
  DISALLOWED / FULL — FULL is permitted only for LOCAL providers).
- Raw evidence: `SANITIZED_ONLY` by default (DISALLOWED drops the
  record; FULL is blocked for external providers and denied for
  SECRET-bearing context).

## Verification (§93)

The golden suite embeds planted secrets (`hunter2fixture`,
`FIXTURE_TOKEN_VALUE_12345`, `AKIAFAKEBINARYFIXTUR`, a private-key
block) in evidence and asserts none of them appears in the
provider-bound payload, the persisted request data, or any GUI-visible
answer.
