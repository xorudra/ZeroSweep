# apps/ai — DSRclone AI analysis service (Python + FastAPI)

Foundation only: service structure, configuration, structured logging and
`GET /health`. **No LLM is connected yet.**

Later phases: the AI layer consumes *normalized findings* (never raw
arbitrary commands) to assist with explanations, risk interpretation,
deduplication, false-positive triage, remediation guidance and summaries.
It never autonomously decides to launch intrusive exploitation.

Run locally:

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --port 8000
pytest -q
```
