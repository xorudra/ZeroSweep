# Network VAPT Authorization (Prompt 33 §7, §129–§131)

Before any active network operation, the authorization chain must hold
end to end:

1. The parent target is VERIFIED (ownership verification precedes
   active testing — Prompt 4 discipline, unchanged).
2. An authorization record exists and is ACTIVE: the APPROVED
   assessment bound to the target.
3. The authorization has not expired (target verification expiry is
   checked from the real record).
4. The target value is covered by the approved scope (the assessment's
   own target).
5. The requested tools and profile are allowed (governed catalog +
   per-capability gates).

RBAC separates the dangerous capabilities: RUN_NETWORK_VULNERABILITY_SCAN,
RUN_HIGH_THROUGHPUT_PORT_SCAN (admins), RUN_CREDENTIALLED_NETWORK_SCAN
(admins), RUN_TARGETED_NETWORK_VERIFICATION, CREATE_PACKET_CAPTURE /
VIEW_PACKET_CAPTURE, and — separately, implying nothing else —
RUN_CONTROLLED_METASPLOIT_VERIFICATION.

Every step is audited (NETWORK_TARGET_CREATED, NETWORK_PREFLIGHT_COMPLETED,
NETWORK_SCAN_PLANNED / STARTED / PARTIAL / CANCELLED, NETWORK_HOST_DISCOVERED,
NETWORK_SERVICE_DISCOVERED, NETWORK_VULNERABILITY_FOUND / VERIFIED,
NETWORK_DRIFT_DETECTED, PACKET_CAPTURE_STARTED / COMPLETED,
CONTROLLED_METASPLOIT_VERIFICATION_REQUESTED; NETWORK_SCAN_COMPLETED is
the Prompt 10 action, reused). Audit metadata never contains
credentials.
