# SearchSploit — Exploit Reference Lookup (Prompt 11 §17–§21)

SearchSploit is integrated as **VULNERABILITY_REFERENCE_LOOKUP only** —
explicitly NOT exploit execution.

- It answers one question: "does a public exploit reference exist for
  this already-identified CVE/product?" (§19: CVE correlation preferred,
  then product/version).
- DSRclone **never executes, downloads, compiles or launches exploit
  code** through SearchSploit. There is no such code path (§18/§103).
- An `ExploitReference` record (finding, source, EDB-ID, title,
  reference, platform/type, verified metadata) means "public exploit
  reference exists" — a **risk signal only**. It must never be presented
  as "CONFIRMED EXPLOITABLE", never proves exploitability on the target,
  and never triggers automatic exploitation (§20/§21). It may raise
  remediation priority via Risk Engine V2's explained factors.
- Lookups read a governed LOCAL reference dataset. The shipped dataset
  is empty: with no governed data, lookups return nothing and no
  references are shown.
