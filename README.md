# BioGuard: Biometric Authentication Threat Detection System

A functional, local cybersecurity interview demo built with **React + Vite**, **FastAPI**, and **SQLite**. Enroll a fictional identity, simulate biometric authentication, investigate rule evidence, contain an account, and demonstrate the audit trail.

**Synthetic data only:** no camera, fingerprint reader, face upload, Aadhaar field, or biometric collection. A template is just a randomly generated `syn_...` reference. Seeded names are fictional, emails use `.test`, and simulated IPs must belong to the RFC 5737 documentation ranges.

## Windows setup

Requirements: Python 3.11+ and Node.js 22+ (Node 24 also works). Run the commands from this project folder in PowerShell. Using `npm.cmd` avoids PowerShell's npm script execution-policy issue. No virtual-environment activation is required.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
npm.cmd ci
```

Start the backend in one terminal:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Start the frontend in a second terminal:

```powershell
npm.cmd run dev
```

Open **http://127.0.0.1:5173** and choose **Enter as demo admin**. FastAPI's interactive API reference is at **http://127.0.0.1:8000/docs**. Keep the same hostname while using the app; sessions are cookie-based.

The frontend proxies `/api` to the backend on port 8000. Both services bind only to loopback. Stop either service with Ctrl+C in its terminal.

To test the production frontend build:

```powershell
npm.cmd run build
npm.cmd run preview
```

Stop the dev frontend first; preview also uses port 5173. Keep the backend running. SQLite initializes and seeds automatically on the first backend startup. Data persists in `backend/bioguard.db` across restarts.

## Two-minute interview walkthrough

1. Sign in as **demo admin**. Explain the dashboard counters, active rules, consent boundary, and synthetic-data banner.
2. Click **Suspicious success** on Overview or Simulation lab. This creates a fresh fictional account, a reviewed baseline workstation, five failed authentication events, and a successful login from an unknown device. It opens the critical investigation automatically.
3. Show **BG-002**, its rule explanation, the **six supporting event IDs**, device/IP details, and the chronological account timeline. BG-001 (failure burst) and BG-003 (new device) also fire.
4. Click **Acknowledge**, then **Lock account**. Add a note such as: “Five failed matches followed by a new-device success. Account contained; evidence retained for review.”
5. Show the **Response audit trail** in the investigation, or close it and open **Audit log**. Filter by the account name or “Account locked”.
6. In **Simulate login**, select that account and choose Successful match. The backend records a **failure** with reason “Account locked by administrator”, demonstrating containment.
7. Optional privacy demonstration: open **Accounts & privacy → Manage**. Withdraw consent or delete the synthetic template; both actions are audited and block authentication. Sign out, enter as **demo analyst**, and request template access to demonstrate a persisted denied event and BG-004 alert.

Each scenario uses a fresh account so that previous locks, consent withdrawals, and detection windows do not make repeated demonstrations unpredictable. The baseline itself is processed through detection and explicitly acknowledged. The “Normal login” scenario therefore leaves no new *open* alert, while retaining an audited first-device baseline.

## Features

- Consent-required enrollment, automatically generated `.test` email and synthetic template reference.
- Login simulator records account, server UTC timestamp, device, documentation IP, result, reason, and actor.
- Server-side deterministic detections with persisted evidence, severity, rule IDs, and acknowledgement state.
- Overview metrics and 24-hour activity chart from database queries; recent-event, alert, and audit tables with search and filters.
- Alert investigation includes both the fixed supporting evidence and the broader account timeline.
- Admin acknowledgement, account lock/unlock, investigation notes, consent withdrawal, and template deletion, with transactional audit records.
- Admin-only template reads; denied analyst reads commit events and alerts before returning HTTP 403. Ordinary account listings never expose template IDs.
- Four repeatable scenario buttons that write real database events, not frontend mock objects.
- Desktop/mobile layout, keyboard-operable native dialogs, error and empty states, and server-pushed live updates with automatic reconnect.
- Optional Shodan InternetDB public-IP enrichment with fixed upstream host, six-second timeout, no redirect following, and explicit unavailable/empty states.

## Detection semantics

| Rule | Severity | Trigger | Evidence |
|---|---|---|---|
| BG-001 | High | Fifth failed login for the same account within an inclusive ten-minute window, including failures separated by successes | All five failure IDs |
| BG-002 | Critical | Successful login after at least three failures in the last ten minutes since the previous successful login | Failure IDs plus the success ID |
| BG-003 | Medium | Successful login from a device with no earlier successful login for that account, including a first-ever device | Triggering successful event; known-device absence is checked server-side |
| BG-004 | High | Denied synthetic-template access, including insufficient role or missing consent/template | Denied access event ID |

BG-001 emits once when the count crosses from four to five. Further failures in the same burst do not duplicate the alert. It can fire again after older failures expire and the threshold is crossed anew. BG-002's failure sequence resets on success. Failed logins do not establish a known device. Template-access events do not count as login failures. Rules use server timestamps, never client-supplied timestamps. Seed and demo baseline timestamps are generated internally. Evidence and alerts commit in the same SQLite write transaction.

Acknowledgement is triage, not resolution: it changes the open-alert count but does not remove evidence or automatically unlock accounts. Templates can be deleted separately from consent withdrawal. Withdrawal immediately blocks authentication and template reads; deletion removes the reference from the account. Both are irreversible for that test account; create a new account for another enrollment.

## OSINT Framework integration

[OSINT Framework](https://osintframework.com/) is a curated directory, not a unified API. BioGuard uses the [Shodan InternetDB API](https://book.shodan.io/developer-apis/internetdb/) from the Shodan tool family for optional IP enrichment.

Open **Threat intelligence**, enter a public IPv4 address (for example `8.8.8.8`), and click **Look up IP**. The backend requests `https://internetdb.shodan.io/{ip}` and displays ports, hostnames, tags, and reported vulnerabilities. No API key is required for this endpoint. Only the explicitly entered IP is transmitted. No account details, notes, or template references are sent. Synthetic/private IPs stay local and produce an explanatory state. Internet access is needed only for enrichment and optional Google Fonts; local fallback fonts and all incident workflows work offline.

OSINT observations are context, not biometric threat evidence. Reported vulnerabilities can be unverified. API unavailability does not affect detection. Live upstream behavior is outside this prototype's control; tests cover successful, unavailable, and local-only lookup paths.

## Tests and verification

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests -q
npm.cmd run build
```

Tests use temporary SQLite databases and cover:

- Exact ten-minute boundary and exclusion of older failures.
- Burst deduplication, intervening successes, per-account isolation, and suspicious-success threshold/reset.
- New-device behavior and denied-template evidence.
- Full incident → evidence → acknowledgement → lock → note → audit workflow.
- Consent, template deletion, server-enforced roles, invalid input, session removal, and cross-origin mutation rejection.
- Repeatable scenarios and mocked enrichment success/failure with no synthetic-IP egress.

Browser verification includes desktop at 1440px, mobile at 390px, scenario generation, response actions, audit search, and explicit-consent enrollment.

## Architecture and API

```text
React / Vite :5173
  └── same-origin /api proxy → FastAPI :8000
       ├── server-owned demo sessions and role checks
       ├── event ingestion → detection → alerts + evidence
       ├── account/privacy/response mutation + audit transaction
       ├── SQLite (WAL, foreign keys, indexed event windows)
       └── optional public-IP-only → Shodan InternetDB
```

| File | Responsibility |
|---|---|
| `backend/main.py` | FastAPI routes, validated input, sessions, role checks, enrichment |
| `backend/detection.py` | Event ingestion and all four detection rules |
| `backend/db.py` | Schema v1 and transactional connection lifecycle |
| `backend/seed.py` | Fictional accounts and historical events |
| `backend/tests/test_detection.py` | Rule and API integration tests |
| `src/main.jsx` | API-connected React views, dialogs and forms |
| `src/styles.css` | Responsive SOC visual system |

Important routes: `POST /api/session`, `GET /api/snapshot`, `POST /api/users`, `POST /api/simulations`, `POST /api/scenarios`, `GET /api/alerts/{id}`, `POST /api/alerts/{id}/acknowledge`, `POST /api/alerts/{id}/notes`, `PATCH /api/users/{id}/lock`, `POST /api/users/{id}/withdraw`, `DELETE /api/users/{id}/template`, `POST /api/users/{id}/template-access`, `GET /api/enrichment/{ip}`. See generated OpenAPI for request bodies.

## Prototype boundaries

The login screen deliberately allows selection of a demo role. The backend stores an opaque, hashed, eight-hour session and enforces that role on subsequent requests, but **role selection is not production operator authentication**. Keep this application on loopback. Deployment would require a real identity provider, TLS/Secure cookies, rate limiting, scoped user ownership, durable migrations, and stronger operational controls.

Audit records are append-only through the application API; a person with direct SQLite file access can modify them. Template deletion removes the active reference, not forensic copies in SQLite free pages or backups. This is a privacy-control demonstration, not certified biometric erasure. Logs intentionally retain synthetic account references and event history. No production biometric matching is performed.

The UI shows the latest 500 alerts/events/audit entries, clearly labeled; dashboard totals query the complete database. Account timelines remain available in investigations. UTC timestamps are stored consistently and displayed in the browser's local timezone. Seed data is added only to an empty database.

For a fresh demo without deleting an existing database, stop the backend and start it with a new database path:

```powershell
$env:BIOGUARD_DB = Join-Path $PWD 'backend\interview-demo.db'
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

If the UI cannot connect, verify both terminals are running and ports 5173/8000 are free. A 401 means the demo session expired; sign in again. A 403 template request is expected for analysts and is itself a detection event.


## Real-time updates

The authenticated `/api/stream` endpoint uses Server-Sent Events (SSE). SQLite transactions notify connected browsers only after a successful commit. Browsers immediately reload API data, including the active investigation, without refreshing the page. Multiple changes during a refresh are coalesced and followed by a catch-up refresh.

The connection indicator shows Connecting, Live, or Reconnecting. EventSource reconnects automatically after a dropped connection; every reconnection fetches a complete snapshot, so changes made while disconnected are recovered. Ten-second heartbeat comments keep idle streams alive, and the server rechecks session validity on each notification/heartbeat. Signing out or expiring a session closes its stream. No synthetic activity is generated just to animate the dashboard.

To demonstrate: open BioGuard in two tabs, open an alert in one, then acknowledge it or add a note in the other. Both update immediately. You can also submit simulator requests through the API and see the dashboard respond.

Run one Uvicorn worker for this prototype: the commit notification broker is in process. A multi-worker deployment would require a shared broker such as Redis. Reverse proxies must disable buffering for `/api/stream`; the endpoint sends `X-Accel-Buffering: no`. The Vite proxy supports this stream unchanged.
