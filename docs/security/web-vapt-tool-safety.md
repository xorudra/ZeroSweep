# Web VAPT Tool Safety (Prompt 32 §70–§104)

The intrusive/exploit/brute/DoS exclusion is **structural**: it lives
in adapter plan construction, not in operator discipline.

## Detection-only adapters

| Tool | Posture |
| --- | --- |
| Dalfox / XSStrike | XSS proof with harmless reflection markers only; no custom payloads, no blind-callback URLs, no persistent payloads (§71) |
| SQLmap | `--technique=B --level≤2 --risk 1`, single parameter. Dumping, file read/write, OS shell/cmd, SQL shell, user/role/password enumeration are **structurally absent and actively rejected** in config validation (§74/§179) |
| Commix | Marker-technique detection; `--os-cmd`, shells, file and registry access rejected (§77/§78/§180) |
| SSTImap | Arithmetic proof marker; code evaluation and OS options rejected (§79) |
| WPScan | Enumeration only (versions, known-vuln correlation, config observations); password attacks rejected (§81/§82) |
| Nuclei | Prompt 7 SAFE template selector, unchanged |

No adapter performs post-exploitation (§80). No password-attack module
exists in the capability registry — Hydra/Medusa/Ncrack/Patator are on
an explicit forbidden list (§104).

## Other bounded checks

- **SSRF (§90/§91):** only the platform's own callback infrastructure
  (workspace-scoped token, expiry, correlation ID, rate limits) —
  never arbitrary internal requests, never cloud-metadata fetches
  (§134).
- **Uploads (§92):** inert fixture files only — no executable content,
  no malware.
- **Traversal (§93):** bounded marker-file proofs; no arbitrary file
  read.
- **Rate-limit analysis (§103):** bounded request counts with minimum
  intervals, inside the plan budget — analysis, never a DoS.
- **GraphQL (§57–§59):** introspection governance unchanged from
  Prompt 9; generated tests bounded by depth/complexity/alias/batch
  limits, rejected at generation time when excessive (§184).
- **JWT (§55/§56):** defensive inspection only; no cracking, no
  brute-force, ever.
