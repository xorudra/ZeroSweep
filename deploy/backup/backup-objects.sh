#!/bin/sh
# ZeroSweep object-storage backup (Prompt 25 §44/§115): mirrors the artifact
# bucket to the backup bucket with server-side encryption expected on the
# destination bucket policy. Uses MinIO Client (mc) or AWS CLI depending on
# OBJECT_BACKUP_TOOL. Bucket versioning + object-lock (WORM) are bucket
# settings applied by the platform operator — see README.md in this folder.
set -eu

SRC_ALIAS="${OBJECT_SRC_ALIAS:-dsrsrc}"
SRC_BUCKET="${MINIO_BUCKET:-zerosweep-artifacts}"
DST="${OBJECT_BACKUP_DEST:?OBJECT_BACKUP_DEST like s3backup/zerosweep-artifacts-backup is required}"
TOOL="${OBJECT_BACKUP_TOOL:-mc}"

case "$TOOL" in
  mc)
    command -v mc >/dev/null 2>&1 || { echo "[objects] FATAL: mc not installed" >&2; exit 1; }
    mc mirror --overwrite --watch=false "$SRC_ALIAS/$SRC_BUCKET" "$DST"
    ;;
  aws)
    command -v aws >/dev/null 2>&1 || { echo "[objects] FATAL: aws cli not installed" >&2; exit 1; }
    aws s3 sync "s3://$SRC_BUCKET" "s3://$DST" --only-show-errors
    ;;
  *) echo "[objects] FATAL: OBJECT_BACKUP_TOOL must be mc or aws" >&2; exit 1 ;;
esac
echo "[objects] mirror complete: $SRC_BUCKET -> $DST"
