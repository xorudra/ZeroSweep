# Wireless Sensor Model (Prompt 19 §11–§14)

A **WirelessSensor** is a dedicated, approved collection device bound to a
`WirelessEnvironment`. Wireless interfaces are never exposed to the web
tier, the API or general workers.

## Lifecycle

`REGISTERED → ACTIVE` (approval). Approval binds the sensor to an
interface name that appears in the environment scope's
`approvedInterfaces` (§12): a sensor whose interface is not allowlisted
cannot be approved. Health is a reported fact (`HEALTHY | DEGRADED |
UNAVAILABLE | UNKNOWN`); with no provisioned sensor transport the honest
value is `UNKNOWN` — the platform never fabricates a feed.

## Worker binding

Only workers holding the `WIRELESS_PASSIVE_ANALYSIS` capability execute
wireless adapters. The executor derives the sensor reference and interface
from the store (newest APPROVED+ACTIVE sensor of the environment) — never
from client input, a plan or a queue payload. Sensor credentials, where a
deployment uses them, are secret references only.

## Kismet instances (§17)

An administrator-managed Kismet server may be registered as a connector
(reference name only). Its transport is deliberately unwired in this
build, so it reports `NOT_CONFIGURED` rather than inventing observations;
collection happens through sensor-local Kismet adapters instead.
