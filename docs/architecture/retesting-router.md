# Retesting Router (Prompt 20 sections 37-39)

`RetestRouter` maps a finding's source domain to the safe retest
engine that can actually verify the fix: web/API -> Prompt 16
validators, network -> targeted scan, code -> repository rescan,
container/cloud/Kubernetes/AD/mobile/binary/wireless -> their
respective governed re-checks. Every retest still passes the normal
gates (verified target, approved assessment, kill switches); the
router never invents a path. Outcomes: RESOLVED (with evidence),
REOPENED (recurrence counted), or INCONCLUSIVE - absence of
evidence is never reported as a fix.
