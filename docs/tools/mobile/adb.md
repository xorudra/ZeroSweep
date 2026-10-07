# ADB — lab devices only (Prompt 17 §59/§60)

Governed operations on approved DSRclone-managed lab devices:
inventory, install of the authorized build (artifact hash verified
first), launch, log collection, cleanup/reset. Dynamic stages only,
on `MOBILE_DYNAMIC_ANALYSIS` workers, inside an approved session.

**There is no generic `adb shell` endpoint** — arbitrary shell is
prohibited automation (§75) and does not exist in DSRclone.
