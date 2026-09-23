# Threat model

STRIDE for the sensor, the API and the UI, plus the model artifacts and notifications they depend
on. Audit IDs (`SEC-01` …) refer to the v1 audit that started the rewrite.

## Scope and assumptions

- **One admin, one machine.** AI-NIDS runs on a laptop, home server or lab VM and has one account.
  There are no roles, and every signed-in request has full rights.
- **The host is trusted.** Anyone with a shell as the service user, or write access to the data or
  artifacts directories, can do everything the software can. The goal is to stop *remote*
  attackers and *other local users* from getting there.
- **The watched network is hostile.** Every packet the sensor parses may have been crafted to
  attack it.

## Assets

| Asset | Why it matters |
|---|---|
| Capture privileges (raw sockets) | Reading all traffic on the host's interfaces |
| Captured metadata: flows, alerts, host IPs | Shows who talks to whom. Personal data on a home network. |
| The admin account and sessions | Full control of the tool |
| Model artifacts (`model.joblib`) | Loaded with pickle, so a malicious file runs code |
| Notification secrets (SMTP password, webhook secret) | Access to third-party accounts |
| Detection integrity | An attacker who can silence alerts or suppress rules goes unseen |

## Components and trust boundaries

```
 watched network ──packets──►  SENSOR  (the only process with NET_RAW / Npcap access)
                                  │ writes flows, alerts, heartbeat
                                  ▼
                         SQLite  data/nids.db  ◄── read/write ──  API  (unprivileged, 127.0.0.1)
                                                                   │ same origin: REST + WebSocket
                                                  artifacts/ ──►   │ + static UI
                                                                   ▼
                                                           browser (the admin)
                           API ──► SMTP server / webhook URL (outbound, admin-configured)
```

Boundaries: **(1)** network → sensor, **(2)** browser → API, **(3)** API → subprocesses (sensor,
jobs), **(4)** filesystem (artifacts, uploads) → API, **(5)** API → outbound notification
endpoints.

## Sensor

| | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S** | Spoofed source addresses frame an innocent host as the attacker | Alerts carry their evidence (ports, SYN/RST ratios, top source share) for the analyst to judge. Floods are attributed to the heaviest sender, and only flooding sources count towards DDoS. | IP spoofing can't be detected at this layer. |
| **T** | Crafted packets corrupt flow state or features | The parser reads fixed header fields only. Malformed packets are counted and skipped. Missing values stay NaN instead of becoming 0. Property tests cover the feature builder. | Scapy (Python) and NFStream/nDPI (C) parse untrusted input. A parser bug in nDPI would be memory corruption. |
| **R** | A capture runs and nobody can tell | Each start creates a session with start/stop times and counters. Starts and stops are written to the audit log. | — |
| **I** | The sensor leaks what it sees | It writes only to the local database. Retention deletes flows after 7 days and alerts after 90. `NIDS_PSEUDONYMIZE_IPS` stores IPs as keyed hashes. | The database file itself is plain SQLite. Protect it with filesystem permissions or disk encryption. |
| **D** | A flood exhausts memory or CPU (CAP-05) | Bounded flow table with LRU eviction, bounded packet queue with counted drops, and at most 10,000 alerts kept in memory. The soak harness checks memory stays flat. | Under overload the sensor drops packets, and so may miss attacks. Drops are shown per session. |
| **E** | A compromised sensor escalates further | Only the sensor has capture rights. On Linux it gets exactly NET_RAW + NET_ADMIN, through a separate `python-capture` binary. In Docker it runs as a non-root user with a read-only filesystem and all other capabilities dropped. On Windows only the sensor runs elevated, and only when Npcap is restricted to Administrators. | On Windows with elevation, a sensor compromise is an Administrator compromise. |

## API

| | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S** | Someone on the LAN uses the API (v1: no auth, `0.0.0.0`, `CORS(*)`, SEC-01) | Binds to `127.0.0.1` by default. Listening elsewhere prints a warning, and Docker publishes on the host's loopback only. Every route except `/healthz`, `/readyz`, `/metrics` and the auth status/setup/login routes needs a session. A test walks every OpenAPI operation to enforce this. | Anyone who can reach the port can try passwords (see D). |
| **S** | First-run setup is replayed to take over the account | `POST /api/auth/setup` refuses once an admin exists (tested) | Between install and setup, whoever reaches the page first creates the admin. Loopback binding limits that to local users. |
| **S** | Session theft | Random 256-bit token in an `HttpOnly`, `SameSite=Strict` cookie, `Secure` when served over HTTPS. The database stores only its SHA-256. Sessions expire after 12 h (configurable). Passwords use argon2id. | Plain HTTP on a LAN exposes the cookie. Use HTTPS in front if you open it up. |
| **T** | Cross-site request forgery | Every state-changing route needs the session's CSRF token in `X-CSRF-Token`, compared in constant time (tested for every write route). The cookie is `SameSite=Strict`, and CORS allows the same origin only. | — |
| **T** | Cross-site WebSocket hijacking | `/api/ws` needs the session cookie and a same-site `Origin`. Extra dev origins must be listed explicitly. | — |
| **T** | Settings changed to dangerous values (v1: `model_path` → code execution, SEC-02/03) | Typed settings with an allow-list of mutable keys and range checks. Paths (model, data, artifacts, frontend) can't be set through the API. | — |
| **T** | Path traversal through uploads, reports or static files (SEC-04) | Uploads are stored under a server-chosen id in a sandbox directory, with a size limit and a PCAP magic-byte check. Jobs refer to uploads by id, never by path. Static and report routes resolve paths and reject anything outside their root (tested). | — |
| **T** | Command injection through job parameters | Jobs run `nids` subprocesses with an argument list (no shell). The capture interface must be one of the listed interfaces, never an arbitrary string. | — |
| **R** | Denying a change was made | The audit log records settings changes (secrets redacted), model activations, starts/stops, alert status changes and suppression rules, with the acting user. | The audit log lives in the same database the admin controls. It doesn't protect against the admin. |
| **I** | Logs or errors leak internals | One error envelope with no stack traces. Log and audit endpoints need auth, and the log tail reads by seeking, capped. Notification secrets are write-only in the API and redacted in the audit log. | `/metrics` is public: open alert counts by severity, and whether the sensor and jobs are running. It's reachable only where the API is. |
| **D** | Password guessing, huge bodies, job floods | 5 login/setup attempts per minute per client. Bodies over 1 MB are refused (uploads have their own limit, 512 MB by default). At most 2 concurrent jobs and 1 sensor. | Job endpoints limit concurrency, not request rate. |
| **E** | Loading a malicious model (pickle, ML-12) | A model can only be activated if it is registered from the artifacts directory, its path resolves inside that directory, its SHA-256 matches its manifest, and its schema hash matches. A test flips one byte and expects 409. | The manifest sits next to the model, so the hash catches corruption and accidental swaps, not someone with write access to `artifacts/` (see assumptions). Moving to `skops` or ONNX would remove pickle altogether. |

## UI

| | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S** | Clickjacking the admin into actions | `X-Frame-Options: DENY` | — |
| **T** | Stored XSS through attacker-controlled strings (hostnames, labels, notes, uploaded file names) | React escapes all rendered text. The only `dangerouslySetInnerHTML` is the constant theme boot script. CSP with no `unsafe-inline` for scripts: the one inline script (the theme boot) is allowed by its hash. Reports are Jinja2 with autoescape, contain no scripts, and are served with a `sandbox` CSP. | — |
| **T** | CSV injection in exports | The API's CSV exports prefix any cell starting with `=`, `+`, `-`, `@`, tab or carriage return with an apostrophe. | — |
| **I** | Secrets in the browser | The CSRF token lives in memory only. `localStorage` holds only the theme and view preferences. Desktop notifications show only while the tab is in the background. | — |
| **I** | The PDF printer fetches remote content | Reports are printed by headless Chromium with a throwaway profile, all DNS blocked, and a 90 s timeout. Its sandbox is off inside Docker, which is acceptable only because the page is our own script-free HTML. | — |

## Notifications

| | Threat | Mitigation | Residual risk |
|---|---|---|---|
| **S** | A receiver can't tell our webhook from a forged one | Webhook bodies are signed with HMAC-SHA256 when a secret is set | Without a secret, bodies are unsigned. |
| **T/I** | Server-side request forgery through the webhook URL | Only the admin can set the URL, and redirects aren't followed | The admin can point it at internal addresses. That's within the admin's rights, so it isn't blocked. |
| **I** | Notification credentials leak | Write-only through the API, redacted in the audit log | **Stored in plain text in the database.** Use an app-specific SMTP password. |
| **D** | Alert storms flood a mailbox or channel | One message per pass, an hourly cap per channel (held-back alerts are counted in the next message), and replays off by default | Delivery is at most once. A failed send isn't retried. |

## Known gaps

- No TLS termination is built in. For anything beyond loopback, put a reverse proxy with HTTPS in
  front and set `NIDS_SECURE_COOKIES=true`.
- Model artifacts are pickles (see API, E).
- Notification secrets are stored unencrypted.
- There is no second factor and no password-reset command. Recovering a lost password means deleting the admin row from the database's `users` table and running setup again.
- The capture parsers (Scapy, and nDPI inside NFStream) are third-party code facing hostile input.
  Keep them updated.
