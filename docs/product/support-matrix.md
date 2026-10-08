# Support Matrix (Prompt 40 §287/§199/§200)

| Component | Supported | Notes |
|---|---|---|
| PostgreSQL | 15, 16 | Primary data store; product tables included in whole-database backups (§247) |
| Redis | 7 | Queues, rate limits, scheduler locks |
| Node.js | 20 LTS+ | API, worker, web |
| Browsers | Current Chrome, Edge, Firefox, Safari | Web console |
| Object storage | S3-compatible (MinIO supported) | Reports/artifacts/exports |
| License signing | Ed25519 | Public key ships with the app; private key never (§30/§248) |

Version compatibility (§198): the API, worker and AI service ship as
one release train (root `package.json` version). Mixed-version
operation across a major boundary is not supported; the upgrade
preflight checks recorded deployment versions (§190).
