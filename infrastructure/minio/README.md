# infrastructure/minio

MinIO provides S3-compatible object storage for scanner artifacts, evidence
and generated reports. The bucket is created by the compose "minio-init"
service; buckets are private by default.
