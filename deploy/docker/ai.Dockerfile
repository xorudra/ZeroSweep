# syntax=docker/dockerfile:1
# DSRclone AI copilot service — production image (Prompt 25 §6–§19).
FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f AS build
WORKDIR /build
RUN python -m venv /venv
COPY apps/ai/requirements.txt ./
RUN /venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim@sha256:05cda9777409a9c3ffddd94a4c476b79f0769a0b4857f0c7ed9226b6800b0d6f AS runtime
LABEL org.opencontainers.image.title="dsrclone-ai" \
      org.opencontainers.image.description="DSRclone AI copilot service (analyst assistant; no execution surface)" \
      org.opencontainers.image.source="https://github.com/xorudra/dsrclone" \
      org.opencontainers.image.licenses="UNLICENSED"
ENV PYTHONUNBUFFERED=1 PATH="/venv/bin:$PATH" NODE_ENV=production
RUN groupadd -r dsrclone && useradd -r -g dsrclone -d /app dsrclone
WORKDIR /app
COPY --from=build /venv /venv
COPY --chown=dsrclone:dsrclone apps/ai/app ./app
USER dsrclone
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3).status==200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
