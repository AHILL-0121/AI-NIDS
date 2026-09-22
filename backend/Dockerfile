# syntax=docker/dockerfile:1.7
#
# One image for both services (audit OPS-01, OPS-03):
#   api     `nids api`: the unprivileged HTTP/WebSocket server, which also serves the UI
#   sensor  `nids sensor`: live capture, started through /app/.venv/bin/python-capture, the only
#           binary that carries the NET_RAW/NET_ADMIN file capabilities
#
# Build from the repo root (docker/compose.yml does this). The UI comes from the `frontend`
# build context:
#   docker build -f backend/Dockerfile --build-context frontend=frontend backend

ARG PYTHON_IMAGE=python:3.12-slim-bookworm
ARG NODE_IMAGE=node:22-bookworm-slim
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.9.30

# --- 1. the UI: Next.js static export ---------------------------------------------------------
FROM ${NODE_IMAGE} AS ui
WORKDIR /ui
COPY --from=frontend package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY --from=frontend . .
RUN npm run build

# --- 2. Python dependencies and the nids package ------------------------------------------------
FROM ${UV_IMAGE} AS uv
FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PYTHON=/usr/local/bin/python3.12
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --extra capture --extra ml --no-install-project
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --extra capture --extra ml --no-editable

# --- 3. runtime ---------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE} AS runtime
ARG WITH_PDF=1
# libpcap: capture; libgomp1: LightGBM; libcap2-bin: setcap; chromium: PDF reports (optional).
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 libgomp1 libcap2-bin \
    $([ "$WITH_PDF" = "1" ] && echo chromium fonts-dejavu-core) \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 nids \
 && useradd --system --uid 10001 --gid nids --home-dir /data --shell /usr/sbin/nologin nids \
 && mkdir -p /data && chown nids:nids /data

COPY --from=build /app/.venv /app/.venv
COPY --from=ui /ui/out /app/frontend
# A separate interpreter with capture capabilities, used only by the sensor. It sits inside the
# venv so it finds the venv's packages. The api service never runs it, so it needs no extra
# capabilities (exec'ing a file whose capabilities the container lacks would fail).
RUN cp "$(readlink -f /app/.venv/bin/python)" /app/.venv/bin/python-capture \
 && setcap cap_net_raw,cap_net_admin+eip /app/.venv/bin/python-capture

ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    NIDS_HOST=0.0.0.0 \
    NIDS_DATA_DIR=/data \
    NIDS_DATABASE_URL=sqlite:////data/nids.db \
    NIDS_ARTIFACTS_DIR=/data/artifacts \
    NIDS_FRONTEND_DIR=/app/frontend \
    NIDS_PDF_NO_SANDBOX=true

USER nids
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=4)"]
ENTRYPOINT ["nids"]
CMD ["api"]
