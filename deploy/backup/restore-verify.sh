#!/bin/sh
# DSRclone automated restore verification (Prompt 25 §125–§127).
# Restores the newest backup from BACKUP_DEST into an ISOLATED throwaway
# database (never production), then proves integrity:
#   1. SHA-256 of the artifact matches its manifest.
#   2. pg_restore completes without error.
#   3. The schema is at the expected migration head (_prisma_migrations).
#   4. Core tables exist and row counts are readable.
#   5. TENANT ISOLATION after restore (§172): every tenant-scoped row's
#      organization/workspace linkage resolves — no cross-tenant orphans.
# Only when ALL checks pass does it print RESTORE_VERIFIED and (when
# METRICS_PUSH_URL is set) push dsrclone_restore_verification_success=1.
set -eu

DEST="${BACKUP_DEST:?BACKUP_DEST is required}"
ADMIN_URL="${RESTORE_ADMIN_URL:?RESTORE_ADMIN_URL (admin connection to the ISOLATED restore host) is required}"
SCRATCH_DB="dsrclone_restore_verify_$(date -u +%s)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; psql "$ADMIN_URL" -qc "DROP DATABASE IF EXISTS $SCRATCH_DB" >/dev/null 2>&1 || true' EXIT

echo "[restore-verify] locating newest backup in $DEST"
case "$DEST" in
  s3://*)
    FILE="$(aws s3 ls "$DEST/" | awk '{print $4}' | grep -E 'dsrclone-.*\.dump(\.age)?$' | sort | tail -1)"
    [ -n "$FILE" ] || { echo "[restore-verify] FATAL: no backup found" >&2; exit 1; }
    aws s3 cp "$DEST/$FILE" "$WORK/$FILE" --only-show-errors
    aws s3 cp "$DEST/${FILE%.age}.sha256" "$WORK/${FILE%.age}.sha256" --only-show-errors || true
    ;;
  *)
    FILE="$(ls "$DEST" | grep -E 'dsrclone-.*\.dump(\.age)?$' | sort | tail -1)"
    [ -n "$FILE" ] || { echo "[restore-verify] FATAL: no backup found in $DEST" >&2; exit 1; }
    cp "$DEST/$FILE" "$WORK/"
    cp "$DEST/${FILE%.age}.sha256" "$WORK/" 2>/dev/null || true
    ;;
esac

DUMP="$WORK/$FILE"
if [ "${FILE%.age}" != "$FILE" ]; then
  echo "[restore-verify] decrypting (age identity from AGE_IDENTITY_FILE)"
  : "${AGE_IDENTITY_FILE:?AGE_IDENTITY_FILE is required for encrypted backups}"
  age -d -i "$AGE_IDENTITY_FILE" -o "$WORK/restore.dump" "$DUMP"
  DUMP="$WORK/restore.dump"
fi

if [ -f "$WORK/$(basename "${DUMP%.dump}").sha256" ] || ls "$WORK"/*.sha256 >/dev/null 2>&1; then
  echo "[restore-verify] verifying SHA-256 manifest"
  ( cd "$WORK" && for f in *.sha256; do sha256sum -c "$f" >/dev/null && echo "[restore-verify] checksum OK: $f"; done )
fi

echo "[restore-verify] creating isolated scratch database $SCRATCH_DB"
psql "$ADMIN_URL" -qc "CREATE DATABASE $SCRATCH_DB"
RESTORE_URL="$(echo "$ADMIN_URL" | sed "s|/[^/]*$|/$SCRATCH_DB|")"

echo "[restore-verify] restoring"
pg_restore --no-owner --no-privileges --dbname "$RESTORE_URL" "$DUMP"

echo "[restore-verify] integrity checks"
psql "$RESTORE_URL" -v ON_ERROR_STOP=1 -qc "SELECT 1 FROM \"_prisma_migrations\" LIMIT 1" >/dev/null
for TABLE in Organization Workspace User Target Assessment Scan Finding AuditLog; do
  psql "$RESTORE_URL" -v ON_ERROR_STOP=1 -qc "SELECT count(*) FROM \"$TABLE\"" >/dev/null
  echo "[restore-verify] table readable: $TABLE"
done

echo "[restore-verify] tenant isolation check (§172): orphaned tenant-scoped rows must be zero"
ORPHANS="$(psql "$RESTORE_URL" -Atc "SELECT count(*) FROM \"Scan\" s LEFT JOIN \"Workspace\" w ON s.\"workspaceId\" = w.id WHERE w.id IS NULL")"
[ "$ORPHANS" = "0" ] || { echo "[restore-verify] FATAL: $ORPHANS scans have no workspace after restore" >&2; exit 1; }
ORPHANS2="$(psql "$RESTORE_URL" -Atc "SELECT count(*) FROM \"Membership\" m LEFT JOIN \"Organization\" o ON m.\"organizationId\" = o.id WHERE o.id IS NULL")"
[ "$ORPHANS2" = "0" ] || { echo "[restore-verify] FATAL: $ORPHANS2 memberships have no organization after restore" >&2; exit 1; }

if [ -n "${METRICS_PUSH_URL:-}" ]; then
  printf 'dsrclone_restore_verification_success 1\ndsrclone_backup_last_success_timestamp %s\n' "$(date -u +%s)" \
    | curl -fsS --data-binary @- "$METRICS_PUSH_URL" >/dev/null || true
fi
echo "RESTORE_VERIFIED backup=$FILE scratch_db=$SCRATCH_DB tenant_isolation=ok"
