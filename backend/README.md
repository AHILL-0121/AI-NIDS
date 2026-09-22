# AI-NIDS backend

Python 3.12 package `nids`: sensor, ML, API and storage. Managed with [uv](https://docs.astral.sh/uv/).

## Setup

```bash
cd backend
uv sync --all-extras         # everything (what tests and CI use)
uv sync                      # core + dev tools
uv sync --extra ml           # add training dependencies
uv sync --extra capture      # add packet capture (NFStream on Linux, Scapy everywhere)
```

## Commands

```bash
uv run nids --help           # list commands
uv run nids doctor           # can this machine capture? what to fix if not
uv run nids interfaces       # capture interfaces (use the --interface value shown)
uv run nids replay file.pcap -o flows.jsonl          # PCAP -> flows (JSON Lines)
uv run nids sensor -i "<interface>" -o flows.jsonl   # live capture; Ctrl+C flushes and stops
uv run nids api              # API on http://127.0.0.1:8000 (GET /healthz, /api/sensor/*)
uv run nids data prepare cicids2017 --src data/raw/cicids2017   # see data/README.md
uv run nids train --dataset cicids2017 --protocol day            # writes artifacts/<version>/
uv run pytest                # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

## Layout

```
src/nids/
  core/     settings, schemas, logging
  sensor/   packets.py (parse), flows.py (flow table), capture/ (scapy, nfstream),
            capability.py (`nids doctor`), interfaces.py, runner.py      (Phases 1, 3)
  ml/       datasets/, prepare, splits, train, evaluate, bundle, registry, model_card (Phase 2)
  api/      FastAPI app, routes, auth, WebSocket   (Phase 5)
  store/    database models, migrations            (Phase 4)
  cli.py    `nids` entry point
tests/
```

Configuration comes from `NIDS_*` environment variables or `backend/.env`. See `.env.example`.

## Capture prerequisites

- **Windows:** install [Npcap](https://npcap.com) with "WinPcap API-compatible Mode".
- **Linux:** libpcap plus `CAP_NET_RAW` (run in Docker with `cap_add: [NET_RAW, NET_ADMIN]`, or
  `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)`), and
  `uv sync --extra capture` for the faster NFStream backend.

PCAP replay needs none of this.
