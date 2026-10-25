# syntax=docker/dockerfile:1
# ZeroSweep scanner worker — production image (Prompt 38 §7/§47/§50–§52).
#
# A DEDICATED scanner-pool image derived from the governed worker image:
# it carries only the tool layer for its pool (selected by the
# SCANNER_POOL build arg and enforced again at runtime by the
# ScannerCapabilityPolicy). Scanner workers are isolated from the API,
# web and database (§50); this image is never privileged (§52), never
# receives a Docker socket, and its egress is governed by the
# authorization architecture (§88/§89) — it is not a general proxy.
#
# Build: docker build -f deploy/docker/scanner-worker.Dockerfile \
#          --build-arg SCANNER_POOL=web-vapt -t zerosweep-scanner-web:38.0.0 .
ARG ZEROSWEEP_VERSION=38.0.0
FROM ghcr.io/xorudra/zerosweep-worker:${ZEROSWEEP_VERSION} AS runtime
ARG SCANNER_POOL=general
LABEL org.opencontainers.image.title="zerosweep-scanner-worker" \
      org.opencontainers.image.version="${ZEROSWEEP_VERSION}" \
      io.zerosweep.scanner-pool="${SCANNER_POOL}"
# The runtime image already runs as the non-root worker user with a
# read-only root filesystem contract; tool binaries for the pool are
# added by the release pipeline as a verified, SBOM-scanned layer
# (Prompt 25 §15) — no package manager runs in this image.
ENV ZEROSWEEP_WORKER_TYPE=SCANNER_POOL_${SCANNER_POOL}
