# GitLab Integration (Prompt 24 §23–§26)

Auth: OAuth application or group/project access token, always as a
secret reference (§24). Project webhooks verify the shared token via
timing-safe comparison.

Merge requests are first-class: an MR event creates the SAME
`PullRequestSecurityAssessment` used for GitHub PRs (§26) — same
baseline classification, same gate engine, same SARIF output.
Group/project sync imports repository metadata into staging rows;
group access never widens the platform's scope — the link table
still decides what may trigger (§25, §86).
