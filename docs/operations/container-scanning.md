# Container Scanning Operations (Prompt 34)

## Flow

1. Register the registry (reference-only credentials) and images on
   the Containers page.
2. Scan via the governed Prompt 13 path (Trivy/Grype/Syft) — or
   Assess on the Container Security page for the V2 pipeline
   (SBOM → vulnerability → configuration → deployment correlation).
3. Read identity by DIGEST: if the digest changed since the last
   scan, it is a different build output — rescan before trusting any
   prior result.
4. Triage by deployment context first (running + public + critical
   CVE), then undeployed images.

## Troubleshooting

- **No SBOM:** the Syft job did not complete or the image has no
  readable layers — coverage shows the gap (TOOL_UNAVAILABLE);
  check worker tool health.
- **Policy violations after a fix:** verification needs a new digest
  + new SBOM + rescan (§122). A re-tag alone changes nothing.
- **Duplicate findings across scanners:** Trivy/Grype duplicates
  merge on package+CVE (§56); if you see two rows, check the
  fingerprints — different packages with the same CVE are correctly
  separate.
- **Registry auth failures:** rotate the reference in Secrets
  Management; the platform never stores the credential itself.
