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
uv run nids replay file.pcap -o flows.jsonl --alerts alerts.jsonl   # PCAP -> flows + alerts
uv run nids sensor -i "<interface>" --alerts alerts.jsonl [--model artifacts/<version>]
                             # live capture + detection; Ctrl+C flushes and stops
uv run nids api              # API on http://127.0.0.1:8000 (GET /healthz, /api/sensor/*)
uv run nids data prepare cicids2017 --src data/raw/cicids2017   # see data/README.md
uv run nids train --dataset cicids2017 --protocol day            # writes artifacts/<version>/
uv run nids report <session> -o report   # report.html (+ report.pdf with Edge/Chrome/Chromium)
uv run pytest                # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

## Tests and coverage

```bash
uv run pytest --cov=nids --cov-report=term       # fails under 75 % overall
uv run coverage report --include="src/nids/core/*" --fail-under=85
uv run coverage report --include="src/nids/sensor/*" --fail-under=85
```

- `tests/fixtures/pcaps/`: labelled captures (benign browsing, nmap SYN scan, hping3 SYN flood,
  masscan-style sweep) replayed through `nids replay`, each with the exact alerts it must raise.
  They are synthetic and rebuilt byte for byte by `uv run python -m
  tests.fixtures.pcaps.make_fixtures`; a test fails if the committed files drift from the script.
- `tests/api/test_security.py` walks every route in the OpenAPI schema: no session gives 401,
  a write without the CSRF token gives 403. A new route without `require_user` fails there.
- `tests/ml/test_regression.py` trains on a frozen synthetic slice and fails if macro-F1 or
  alert precision/recall drop more than 0.03 below `regression_baseline.json`. After a deliberate
  change, run it with `NIDS_UPDATE_BASELINE=1` and commit the new baseline with the reason.
- `tests/soak/`: a long replay loop that checks memory stays flat. Skipped unless
  `NIDS_SOAK_SECONDS` is set (e.g. 21600 for the 6 h run).

## Layout

```
src/nids/
  core/     settings, schemas, logging
  sensor/   packets.py (parse), flows.py (flow table), capture/ (scapy, nfstream),
            capability.py (`nids doctor`), interfaces.py, runner.py      (Phase 1)
            detect/  scan, flood, ml, correlator, knowledge, engine          (Phase 3)
  ml/       datasets/, prepare, splits, train, evaluate, bundle, registry, model_card (Phase 2)
  api/      FastAPI app, routes, auth, WebSocket   (Phase 5)
  store/    database models, migrations            (Phase 4)
  reports/  session report (HTML template, PDF via a headless browser)   (Phase 8)
  notify/   email / webhook notifications, daily digest                  (Phase 8)
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
