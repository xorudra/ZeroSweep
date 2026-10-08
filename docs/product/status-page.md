# Status Page (Prompt 40 §163/§164)

- Route: `/status` in the web app.
- Components: Web App, API, Scanning, Reports, AI, Integrations.
- Source: the deployment health endpoint (measured checks). A
  component that cannot be measured displays "unknown", never a
  fabricated "operational".
- Uptime history, where published, must come from the operator's
  monitoring system of record — this repository does not synthesize
  historical uptime.
