# radare2 (Prompt 18 §33/§34)

Static analysis via typed profiles ONLY. The adapter composes the
command line from the approved operation catalog (`iIj;iSj;iij;iEj;
aflj;isj` for the STANDARD profile: metadata, sections, imports,
exports, functions, symbols) and runs `r2 -2 -q -c <ops> --
<artifact reference>`.

- Unrestricted r2 commands are inexpressible: unknown operations or
  profiles raise `AdapterConfigurationError` at plan time, and
  API-level command fields are refused + audited (§93/§114).
- Output is the recorded per-operation JSON envelope, parsed by
  `parseRadare2Report` into the shared binary inventory.
