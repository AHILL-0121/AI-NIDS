# AI-NIDS backend

Python 3.12 package `nids`: sensor, ML, API and storage. Managed with [uv](https://docs.astral.sh/uv/).

## Setup

```bash
cd backend
uv sync                      # core + dev tools
uv sync --extra ml           # add training dependencies
uv sync --extra capture      # add packet capture (NFStream on Linux, Scapy everywhere)
```

## Commands

```bash
uv run nids --help           # list commands
uv run nids api              # API on http://127.0.0.1:8000 (GET /healthz)
uv run pytest                # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

## Layout

```
src/nids/
  core/     settings, schemas, logging
  sensor/   capture, flows, features, detectors   (Phases 1, 3)
  ml/       datasets, training, evaluation         (Phase 2)
  api/      FastAPI app, routes, auth, WebSocket   (Phase 5)
  store/    database models, migrations            (Phase 4)
  cli.py    `nids` entry point
tests/
```

Configuration comes from `NIDS_*` environment variables or `backend/.env`. See `.env.example`.
