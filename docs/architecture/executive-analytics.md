# Executive Analytics (Prompt 20 sections 71-83)

Four dashboards (executive, security operations, remediation, asset
risk) aggregate stored canonical findings through the SDK analytics
module: severity/status/domain distributions, MTTR, MTTT, reopen
rate, SLA posture, top risky assets, 30-day trends and periodic
`RiskSnapshot` rows for history. Coverage metrics are ratios over
KNOWN denominators - when the denominator is unknown the percentage
is null and the UI shows a dash, never 100% (section 80). Global
search spans findings, assets, repositories, cloud resources,
mobile apps and binary hashes, always inside the caller's tenant.
