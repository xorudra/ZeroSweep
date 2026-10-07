# MobSF (Prompt 17 §13–§17)

Connector over HTTP to an administrator-registered **ScannerInstance**
(trusted MobSF instance; instance credentials are secret references
resolved inside the worker). DSRclone submits **authorized artifacts
only** and imports the report (permissions, components, certificate,
network-security config, code findings, secrets metadata). Unconfigured
instances report NOT_CONFIGURED — never a fabricated scan. MobSF
observations deduplicate with JADX/apktool/platform observations of
the same issue into one canonical finding (§50).
