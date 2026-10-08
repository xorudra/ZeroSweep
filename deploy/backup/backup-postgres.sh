#!/bin/sh
# DSRclone PostgreSQL backup (Prompt 25 §115–§123).
# - pg_dump in custom format from a DEDICATED backup credential
#   (BACKUP_DATABASE_URL — read/replication role, separate from the app's).
# - SHA-256 integrity manifest written beside the dump.
# - Optional client-side encryption: when BACKUP_AGE_RECIPIENT is set the
#   dump is encrypted with `age` before upload; keys are NEVER stored with
#   the backup (§131 — key recovery is a separate, split-knowledge process).
# - Upload target: BACKUP_DEST as an s3:// URL (aws cli) or a local path
#   (mounted WORM/object-lock storage). A backup is only "healthy" after
#   restore verification (restore-verify.sh) passes — upload success alone
#   does not update the success timestamp (§123).
set -eu

: "${BACKUP_DATABASE_URL:?BACKUP_DATABASE_URL (dedicated backup credential) is required}"
DEST="${BACKUP_DEST:?BACKUP_DEST (s3://bucket/prefix or local directory) is required}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DUMP="$WORK/dsrclone-$STAMP.dump"

echo "[backup] dumping (custom format)"
pg_dump --format=custom --no-owner --no-privileges "$BACKUP_DATABASE_URL" > "$DUMP"

echo "[backup] integrity manifest"
( cd "$WORK" && sha256sum "$(basename "$DUMP")" > "$(basename "$DUMP").sha256" )

OUT="$DUMP"
if [ -n "${BACKUP_AGE_RECIPIENT:-}" ]; then
  command -v age >/dev/null 2>&1 || { echo "[backup] FATAL: BACKUP_AGE_RECIPIENT set but age is not installed" >&2; exit 1; }
  echo "[backup] encrypting with age (recipient from environment)"
  age -r "$BACKUP_AGE_RECIPIENT" -o "$DUMP.age" "$DUMP"
  OUT="$DUMP.age"
fi

echo "[backup] uploading to $DEST"
case "$DEST" in
  s3://*)
    command -v aws >/dev/null 2>&1 || { echo "[backup] FATAL: aws cli required for s3:// destinations" >&2; exit 1; }
    aws s3 cp "$OUT" "$DEST/$(basename "$OUT")" --only-show-errors
    aws s3 cp "$DUMP.sha256" "$DEST/$(basename "$DUMP").sha256" --only-show-errors
    ;;
  *)
    mkdir -p "$DEST"
    cp "$OUT" "$DEST/"
    cp "$DUMP.sha256" "$DEST/"
    ;;
esac

echo "[backup] uploaded: $(basename "$OUT")"
echo "[backup] NEXT: run restore-verify.sh — this backup is UNVERIFIED until a restore test passes (§123/§126)."
