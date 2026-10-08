# Response Engine (Prompt 28 §74–§82)

## Closed catalog (§75/§76)

Response is a closed catalog of nine predefined, platform-internal,
defensive actions: disable a DSRclone API key, revoke a DSRclone
session, disable a DSRclone service account, pause an integration,
pause scan automation, create a remediation ticket, send a
notification, request credential rotation, mark an asset for
review. There is no generic shell, script, remote-command or
arbitrary-HTTP step anywhere in the engine — an action key outside
the catalog is rejected at proposal time. External containment
(host/directory actions) is out of scope until dedicated approved
connectors exist.

## Approval policy (§77–§80)

Each catalog entry declares `NO_APPROVAL`, `SINGLE_APPROVAL` or
`DUAL_APPROVAL`. The SDK policy evaluator enforces segregation of
duties: the proposer's approval never counts for their own
high-impact action, duplicate approvals from one approver count
once, and rejected decisions close the request. Execution requires
the `EXECUTE_RESPONSE_ACTION` permission and an `APPROVED` state —
executing early returns the recorded state instead of acting (§146).

## Idempotency & rollback (§81/§82)

Every proposal carries an idempotency identity
(`incident + action + target + nonce`): re-proposing returns the
existing execution, and re-executing an executed action is a
recorded no-op. Each catalog entry documents its rollback path;
rollback is tracked on the execution record honestly (e.g. an API
key is re-enabled through credential administration, not by an
undo button pretending the revocation never happened). Effects are
tenant-checked at execution time — an API key, session, account,
integration or schedule outside the caller's tenant cannot be
touched. Remediation tickets go through the P24 exactly-once path
and report `NOT_CONFIGURED` when no enabled Jira integration
exists, rather than creating orphan tickets.
