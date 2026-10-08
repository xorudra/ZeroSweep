# RC1 dependency audit (Prompt 39 §181/§185/§270)

Tool: `pnpm audit` against the committed `pnpm-lock.yaml`
(first run of the RC1 session — the registry audit endpoint later
began returning HTTP 403 from this environment's proxy, see RC1-I2).

## Result (successful run)

- **Total advisories: 22 — 0 critical, 9 high, 10 moderate, 3 low/info**
- Flagged modules (all transitive): `next` (vendored `postcss` <8.5.10
  CSS-stringify XSS — moderate GHSA-qx2v-qp2m-jg93 class; optional
  `sharp` memory-exhaustion advisories), `body-parser` (DoS via
  urlencoded parsing), `qs` (DoS — installed copy is 6.14.2, at/above
  the patched 6.14.1 for the flagged range; flagged via body-parser's
  declared range), `jws` (HMAC verification — installed copies are
  3.2.3 and 4.0.1, the patched releases for their lines), and the
  markdown toolchain chain (`linkify-it`, `mdast-util-to-hast`,
  `micromark-extension-gfm-autolink-literal` → `path-to-regexp` ReDoS —
  build/docs tooling only).

## Disposition

- No CRITICAL advisories. (§185 satisfied by this document +
  rc1-findings.md.)
- HIGH cluster disposition: **RC1-H1 — ACCEPTED for RC1** with the
  exposure analysis recorded in `docs/release/rc1-findings.md`
  (build-time-only processing of platform-owned assets; vendored code
  not override-patchable; fix path is the Next 15/16 upgrade train,
  scheduled post-RC1).
- Lockfile: `pnpm-lock.yaml` is committed and installs reproducibly
  with `--frozen-lockfile` semantics (§182).
- License inventory: `license-inventory.json` (617 components — all
  permissive: MIT/ISC/Apache-2.0/BSD/CC0; one UNKNOWN, `pause@0.0.1`,
  whose package metadata carries no license field).
- Release SBOM: `sbom.cyclonedx.json` (CycloneDX 1.5, generated from
  the installed tree by `scripts/release/generate-sbom.mjs`).
