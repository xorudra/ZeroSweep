# SmbMap

**Posture:** DEFENSIVE — share inventory only (Prompt 15)

SmbMap is used for share INVENTORY only (§44): share names and the
caller's effective permission level. The governed flag set is fixed
(`-H <host> -P 445 -q`); content listing, download/upload, deletion
and recursive drive flags are refused at plan time and asserted
absent by tests. Share contents are never browsed, read or
downloaded anywhere in the platform.
