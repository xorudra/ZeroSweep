# Production TLS (Prompt 38 §56, §121)

- TLS terminates at the operator's ingress/LB (cert-manager or the
  cloud LB). The platform requires HTTPS public origins
  (`API_CORS_ORIGIN` must be https in production — config gate).
- Internal hops use TLS when they leave the node (DB/Redis TLS flags
  in the config gate); MinIO/S3 endpoints should be https in
  distributed deployments.
- Certificates: automate issuance + renewal; the
  `ZerosweepCertificateExpiringSoon` alert fires at <14 days (§121).
  HSTS and TLS ≥1.2 are ingress settings — the readiness checklist
  (§240) requires confirming them at go-live.
