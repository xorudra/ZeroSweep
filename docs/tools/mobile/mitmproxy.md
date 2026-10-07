# mitmproxy (Prompt 17 §62–§68)

Lab proxy for mobile traffic sessions (reuses the Prompt 9 proxy
connector discipline). Captures flow **metadata** on the isolated
lab network; traffic is sanitized by default (no sensitive bodies).
TLS interception uses a temporary lab CA, removed after the session
— never installed on personal devices (§67).
