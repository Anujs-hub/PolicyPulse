# PolicyPulse - Adaptive Zero-Trust Access Engine

PolicyPulse is an **educational policy simulator** that evaluates simulated access requests using zero-trust
principles and returns an explainable decision: `ALLOW`, `DENY` or `STEP_UP` (extra verification such as MFA).

> **Security disclaimer.** PolicyPulse is a learning prototype, **not** a production security gateway.
> User identity, role, MFA status and device trust are *values typed into a form*. They are **not** verified:
> there is no login, no real MFA, and no device attestation. Do not put it in front of real resources
> or use it to protect anything.

## Problem statement and motivation

Traditional perimeter security trusts anything "inside the network". Zero trust replaces that with
*never trust, always verify*: every request is judged on identity, device posture, resource sensitivity
and context, using least privilege. This project turns those ideas into something you can poke at:
change one input (an untrusted device, a missing MFA, five failed logins) and watch the decision, risk score
and reasoning change - with every evaluation written to an audit log.

## Features

- **Deterministic policy engine** with explicit precedence and fail-closed behaviour.
- **Explainable decisions**: decision, 0-100 risk score with per-factor breakdown, matched rules, plain-English
  explanation, remediation advice, timestamp and unique request ID.
- **RBAC** (admin / analyst / employee) over 7 example resources of four sensitivity levels, enforced on the backend.
- **Dashboard**: totals, decision counts, 7-day timeline, decision mix, risk distribution, policy activity, recent decisions.
- **Access simulator** with five one-click scenarios.
- **Policy management**: view, create, edit, enable/disable and delete policies. Policies are validated *data*
  (whitelisted fields and operators); no user-supplied code is ever executed.
- **Audit log**: SQLite persistence, search, filters, pagination, CSV export with formula-injection protection.
- **REST API** with Swagger UI, strict Pydantic validation, safe error responses, request-size limits.
- Automated test suite using isolated temporary databases (no network, deterministic).

## Architecture

```
Browser (HTML/CSS/JS + vendored Chart.js)
   |  fetch() JSON                       server-rendered pages (Jinja2)
   v                                         v
FastAPI app (app/main.py)  -- middleware: size limit, security headers, CORS, error handling
   |
   +-- api/routes.py      REST endpoints, query validation
   +-- api/pages.py       HTML pages
   |
   +-- services/policy_engine.py     pure function: (request, rules) -> decision
   +-- services/risk_scoring.py      additive risk model
   +-- services/policy_validation.py whitelist validation of conditions
   +-- services/policy_service.py    policy CRUD + mandatory-policy protection
   +-- services/audit_service.py     persistence, search, dashboard stats, CSV export
   +-- services/catalog.py           roles, resources, RBAC matrix (demo data)
   |
   +-- models/ (SQLAlchemy)  ->  SQLite (policies, audit_logs)
```

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Policy evaluation flow

1. The request is validated by Pydantic (`EvaluationRequest`): unknown roles/resources, bad types, extra fields -> HTTP 422.
2. The engine builds a context: sensitivity of the resource, whether RBAC permits the role/action, and the **risk score**.
3. **`SYS-RBAC`** (hard-coded, not stored in the DB, cannot be disabled) adds a DENY if the role lacks the permission.
4. Every enabled policy (and every *mandatory* policy, regardless of its flag) whose conditions all match is collected.
5. **Resolution by effect severity**: any matched `DENY` -> `DENY`; else any `STEP_UP` -> `STEP_UP`; else any `ALLOW` -> `ALLOW`;
   else **`SYS-DEFAULT-DENY`** (fail closed). Priority numbers (lower = first) order rules *within* an effect;
   an `ALLOW` can never override a `DENY` or `STEP_UP`, whatever its priority.
6. The explanation and remediation are generated from the decisive rules and the result is stored in the audit log.

Full model: [docs/POLICY_MODEL.md](docs/POLICY_MODEL.md).

## Risk scoring

`score = min(100, sum of factor points)`

| Factor | Points |
|---|---|
| Resource sensitivity | low 0, medium 10, high 20, critical 30 |
| Requested action | read 0, write 5, delete 10, admin 15 |
| Device trust | trusted 0, unmanaged 15, untrusted 25 |
| MFA not verified | +15 |
| Failed logins | 5 each, capped at 25 |
| Access context | normal 0, unusual_time 8, unusual_location 15, anonymized_network 20 |
| RBAC violation | +20 |

Levels: **0-29 low, 30-59 medium, 60-79 high, 80-100 critical.** The weights are illustrative, chosen to be easy to reason about.

## Technology stack

Python 3.11+, FastAPI, Uvicorn, SQLAlchemy 2, SQLite, Pydantic v2 / pydantic-settings, Jinja2, vanilla HTML/CSS/JavaScript,
Chart.js 4.4.7 (vendored in `app/static/vendor`, so the UI works offline), Pytest, Docker / Docker Compose (optional).
No paid services or API keys.

## Project structure

```
PolicyPulse/
├── app/
│   ├── main.py              app factory, middleware, error handlers
│   ├── config.py            settings (env vars / .env)
│   ├── database.py          engine, sessions, init + seeding
│   ├── models/              SQLAlchemy models (Policy, AuditLog)
│   ├── schemas/             Pydantic request/response models
│   ├── api/                 routes.py (REST), pages.py (HTML), deps.py
│   ├── services/            policy_engine, risk_scoring, policy_validation, policy_service,
│   │                        audit_service, catalog, default_policies, scenarios
│   ├── templates/           Jinja2 pages
│   └── static/              css/, js/, vendor/ (Chart.js)
├── tests/                   pytest suite
├── scripts/                 init_db.py, seed_demo_data.py
├── docs/                    ARCHITECTURE, POLICY_MODEL, THREAT_MODEL, API, TESTING
├── data/                    SQLite file is created here at first start
├── requirements.txt  pytest.ini  .env.example  .gitignore  .dockerignore
├── Dockerfile  docker-compose.yml  LICENSE  README.md
```

## Prerequisites

- Python **3.11 or newer** (check with `python --version` or `py -3.11 --version`)
- Windows PowerShell (commands below), or any shell on macOS/Linux
- Optional: Docker Desktop

## Setup on Windows PowerShell

Open PowerShell in the folder where you extracted the ZIP, then:

```powershell
cd .\PolicyPulse

# 1. Create a virtual environment
py -3.11 -m venv .venv          # or: python -m venv .venv

# 2. Activate it
.\.venv\Scripts\Activate.ps1
# If PowerShell blocks the script, allow it for this window only and retry:
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. (Optional) custom settings
Copy-Item .env.example .env

# 5. (Optional) fill the dashboard with demo data
python scripts\seed_demo_data.py

# 6. Start the server
uvicorn app.main:app --reload
```

- Application: <http://127.0.0.1:8000>
- Swagger UI (API docs): <http://127.0.0.1:8000/docs>
- Health check: <http://127.0.0.1:8000/health>

The SQLite database `data/policypulse.db` and the default policies are created automatically on first start.
To reset everything, stop the server and delete `data\policypulse.db`.

On macOS/Linux use `python3 -m venv .venv && source .venv/bin/activate` instead of steps 1-2.

## Running the tests

```powershell
python -m pytest
```

Useful variants: `python -m pytest -v`, `python -m pytest tests/test_policy_engine.py`,
`python -m pytest -k mandatory`. Tests create a throw-away SQLite file per test (pytest `tmp_path`),
never touch `data/policypulse.db`, and need no network. See [docs/TESTING.md](docs/TESTING.md).

## Docker

```powershell
docker compose up --build       # then open http://localhost:8000
docker compose down             # stop (the database lives in the named volume policypulse-data)
docker compose down -v          # stop and delete the stored database
```

## Example scenarios (simulator)

| # | Scenario | Expected |
|---|---|---|
| 1 | Analyst reads `siem-dashboard`, trusted device, MFA verified | **ALLOW** (risk 10) |
| 2 | Analyst reads `customer-db` from an **untrusted** device | **DENY** (mandatory `P-002`, risk 45) |
| 3 | Analyst with **5 failed logins** | **DENY** (mandatory `P-001`, risk 35) |
| 4 | Admin does an `admin` action on `prod-admin-console` **without MFA** | **STEP_UP** (risk 60) |
| 5 | Employee **writes** to `finance-ledger` | **DENY** (`SYS-RBAC`, risk 45) |

## API examples

PowerShell:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health

$body = @{ user_id="alice"; role="admin"; resource_id="prod-admin-console"; action="admin";
           device_trust="trusted"; mfa_verified=$false; failed_logins=0; access_context="normal" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/evaluate -ContentType "application/json" -Body $body

Invoke-RestMethod "http://127.0.0.1:8000/api/audit-logs?decision=DENY&page_size=5"
Invoke-WebRequest "http://127.0.0.1:8000/api/audit-logs/export?decision=DENY" -OutFile audit.csv
```

curl (use `curl.exe` in PowerShell):

```bash
curl -s -X POST http://127.0.0.1:8000/api/evaluate -H "Content-Type: application/json" \
  -d '{"user_id":"bob","role":"analyst","resource_id":"siem-dashboard","action":"read","device_trust":"trusted","mfa_verified":true,"failed_logins":0,"access_context":"normal"}'
```

Full reference: [docs/API.md](docs/API.md).

## Configuration

Environment variables (prefix `POLICYPULSE_`) or `.env`; see `.env.example`. Defaults are safe for local use.
CORS only allows the origins listed in `POLICYPULSE_CORS_ORIGINS` (a `*` entry is ignored).

## Limitations and security disclaimer

- **Not authentication.** Identity, MFA and device trust are self-asserted form values. There are no sessions, users, passwords or tokens.
- **No real device attestation** and no integration with identity providers, EDR or MDM.
- **No access control on the management UI/API.** Anyone who can reach the server can create policies and read audit logs.
  Run it on localhost only; the default CORS list and the lack of authentication are not a security boundary.
- Risk weights and the RBAC matrix are illustrative, not calibrated against real data.
- The request-size limit relies on the `Content-Length` header; there is no rate limiting.
- SQLite is single-node and unsuited to concurrent production workloads.
- Dashboard "policy activity" is computed over the most recent `POLICYPULSE_DASHBOARD_ACTIVITY_WINDOW` (default 1000) audit rows.
- Swagger UI (`/docs`) loads its assets from a public CDN, so it needs internet access; the rest of the app works offline.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Verification status

Checked in the packaging environment (Linux, Python 3.12.3, dependencies pinned in `requirements.txt`):

- `python -m pytest`: **220 tests passed** (run before the archive was built, and again from the extracted archive).
- Python and JavaScript sources pass syntax checks (`compileall`, `node --check`).
- The server was started with Uvicorn; `/`, `/simulator`, `/policies`, `/audit`, `/health`, `/docs` and `/api/dashboard` returned HTTP 200,
  and `/api/evaluate` returned the expected decisions for the five sample scenarios.

**Not verified in that environment** (please check on your machine):

- The UI was not opened in a real browser, so layout and the JavaScript behaviour of the pages (charts, dialogs, filters) are untested beyond the checks above.
- The Docker image and Compose file were not built or run (no Docker available).
- The Windows PowerShell commands were not run on Windows, and Python 3.11 specifically was not used (3.12 was).

## License

MIT - see [LICENSE](LICENSE). Chart.js is MIT licensed (`app/static/vendor/chart.js.LICENSE.md`).
