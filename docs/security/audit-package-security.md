# Audit Package Security (Prompt 26 §96–§101/§132/§133)

An audit evidence package is a self-contained, tamper-evident bundle:

- **Contents**: assessment snapshot, control results, approved
  evidence snapshots only, risk exceptions, appendices, and a
  metadata/disclaimer header. Redaction passes over every string
  (platform evidence redaction: headers, bearer/basic credentials,
  JSON secret fields, form/query secrets) before sealing (§96).
- **Classification**: the package is CONFIDENTIAL by default (§97).
- **Integrity manifest**: each content file is hashed (SHA-256 over
  its exact bytes) into a manifest; manifest entries are sorted and
  the manifest root hash is stored on the package row.
  `verifyPackageIntegrity` reconstructs the manifest from the stored
  bundle: any modification, addition or removal of a sealed file
  fails verification (§100/§133).
- **Provenance**: every evidence item carries its collector, source
  type, source id, collection time and hash, so an auditor can trace
  any packaged item back to the platform record it snapshots (§101).
- **Access**: packages download only through the auditor-grant /
  package-permission path; downloads increment an audited counter.
