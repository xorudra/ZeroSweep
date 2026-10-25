# Mobile Device Lab (Prompt 17 §53–§61)

## Scope

The lab contains **ZeroSweep-managed emulators and dedicated lab
devices only**. Personal devices are never targeted, never
instrumented and never receive the ZeroSweep CA (§55/§67). Devices
sit on an isolated, dedicated test network (§54).

## Worker separation

`MOBILE_STATIC_ANALYSIS` and `MOBILE_DYNAMIC_ANALYSIS` are separate
worker capabilities (§53). Dynamic workers are more strongly
isolated; a static worker can never execute a dynamic stage, and
vice versa — the executor refuses cross-capability work and the
stage completes degraded with an explicit reason.

## Session governance (§58/§73)

A dynamic session exists only when ALL of these hold: authorized
application build, registered lab device, approved dynamic profile,
valid authorization, instrumentation-policy approval (when modules
are requested), no active kill switch, and budget/timeout bounds.
The API records the session as APPROVED or BLOCKED with reasons;
blocked requests are audited (`MOBILE_DYNAMIC_ACTION_BLOCKED`).

## ADB (§59/§60)

The ADB adapter performs governed operations only: device
inventory, approved-build install, launch, log collection, cleanup.
**There is no generic `adb shell` endpoint anywhere.** Before
install, the lab verifies the artifact hash matches the approved
build. After the assessment the device is reset (§57); cleanup
state is recorded on the session.

## Test data (§61)

Test accounts are secret references only. Synthetic test data is
preferred; real user data is never used in the lab.
