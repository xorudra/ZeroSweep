# CloudMapper Connector (Prompt 14 §27)

## Purpose
AWS account-graph import: CloudMapper's collected account data
(public nodes, network structure) becomes exposure evidence in the
cloud asset graph.

## Capabilities
`AWS_NETWORK_ANALYSIS`, `AWS_ACCOUNT_VISUALIZATION`,
`PUBLIC_EXPOSURE_ANALYSIS`

## Supported target types
AWS (registered cloud accounts)

## Risk level
PASSIVE — an import connector over recorded exports; it opens no live
connection.

## Execution mode
EXTERNAL_API (import). The connector reads a recorded CloudMapper
export from the worker artifact store. With no export available it
reports **NOT_CONFIGURED / unavailable honestly** — import connectors
never fabricate data.

## Output handling
Public nodes in the export become exposure evidence attached to the
matching inventory resources (evidence-backed edges only, §85);
unmatched nodes are recorded as observations, never silently merged.
