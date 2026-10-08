# Deployment scripts (Prompt 25)

| Script | Purpose |
|---|---|
| `preflight.sh` | Operator-side gate: env-file completeness, placeholder rejection, compose parse — never prints secret values (§30/§165). |
| `migrate.sh` | Container entrypoint of the migrate image: preflight → `prisma migrate deploy` → post-check (§36–§39). |
| `release-manifest.mjs` | Emits `release-manifest.json`: version, git commit, image refs/digests (from the build system), migration head, worker version, tool-inventory count (§144–§146). |

## Image security pipeline (§18)

Run in CI for every release image, failing the release on violation:

```sh
# Scan (fail on fixable CRITICAL)
trivy image --severity CRITICAL,HIGH --exit-code 1 ghcr.io/xorudra/dsrclone-api:<version>
grype ghcr.io/xorudra/dsrclone-api:<version> --fail-on critical
# SBOM (attach to the release + record the reference in the manifest)
syft ghcr.io/xorudra/dsrclone-api:<version> -o spdx-json > sbom-api.spdx.json
# Sign (keyless OIDC in CI) — admission verifies (deploy/policies)
cosign sign ghcr.io/xorudra/dsrclone-api:<version>
```

`release-manifest.mjs` never fabricates digests/SBOM references: fields
stay null and the manifest carries an explicit warning until the build
system supplies them.
