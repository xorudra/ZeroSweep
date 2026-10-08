# AI incident response (Prompt 36 §146–§153)

## Suspected AI safety incident

1. **Contain**: disable the workspace's providers (AI settings) or
   set the workspace policy to local-only. The copilot degrades to
   labelled RULE_BASED answers over governed data — analysis
   continues, provider egress stops.
2. **Preserve**: traces (metadata), request logs and audit entries
   are append-only; export the workspace's AiSecurityTrace +
   AiRequestLog + audit rows for the window. Prompts/responses are
   not stored in traces by design — use request logs' metadata.
3. **Classify**: injection attempt (detector counters), data
   exposure (check redaction counts + provider policy), unauthorized
   action attempt (gateway BLOCKED verdicts — the action did not
   happen; verify via proposals/workflows), cross-tenant probe
   (retrieval dropped reasons).
4. **Eradicate/Recover**: rotate any provider credential REFERENCE
   whose value may be implicated (values live in the secret store),
   re-run the V2 evaluation suite, and only re-enable providers when
   all safety cases pass.
5. **Review**: feed the case into the evaluation suite as a new
   regression case before closing (§118).
