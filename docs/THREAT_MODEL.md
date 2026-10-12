# Threat Model

PolicyPulse is an educational simulator. This document states what it defends against, what it does not, and why.

## Scope and assumptions

- Intended for local use by one learner. It has **no authentication** on the UI or API.
- All identity, MFA and device-trust values are **self-asserted inputs**. The simulator makes decisions *about* them; it cannot verify them.

## Assets

Policy definitions (integrity), audit-log records (integrity, accuracy), and the server process (availability).

## Threats and mitigations

| # | Threat | Mitigation in this project | Residual risk |
|---|---|---|---|
| T1 | Code injection via policy expressions | Policies are JSON data with whitelisted fields/operators/typed values; no `eval`/`exec`; engine uses a fixed operator table | None known for the expression path |
| T2 | Bypass of mandatory denials (disable, lower priority, shadow with ALLOW) | Mandatory policies immutable via API; effect-severity precedence; engine ignores the `enabled` flag for mandatory rules; hard-coded `SYS-RBAC`; fail-closed default | Direct database edits can delete mandatory rows (the system rule `SYS-RBAC` and default-deny remain) |
| T3 | Over-permissive custom ALLOW policy | ALLOW policies must include `rbac_permitted = true`; DENY/STEP_UP still win | Admin can still create permissive ALLOWs within RBAC |
| T4 | SQL injection | SQLAlchemy ORM with bound parameters; LIKE wildcards escaped; tested | - |
| T5 | XSS via stored audit/policy text | Frontend inserts data with `textContent`/DOM APIs only; strict CSP (`script-src 'self'`, no inline scripts/styles) | Third-party Swagger UI from a CDN is out of the app's CSP scope |
| T6 | CSV/formula injection from exports | Cells starting with `= + - @ TAB CR` are prefixed with `'`; all fields quoted | Spreadsheet apps may still show the apostrophe |
| T7 | Oversized or malformed input | Pydantic strict types, length/range limits, `extra="forbid"`, 64 KB body cap (Content-Length), page-size caps, export row cap | Chunked uploads without Content-Length are not size-checked; no rate limiting |
| T8 | Information disclosure through errors | Sanitised 422 bodies; generic 500 with `error_id`; stack traces only in server logs | Server logs contain traces |
| T9 | Cross-origin abuse from a malicious web page | Explicit CORS origin list, no credentials; `*` ignored | Without authentication any local process/page that can reach the port can call the API (e.g. via non-browser clients) |
| T10 | Clickjacking / MIME sniffing | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `nosniff` | - |
| T11 | Secrets leakage | No secrets or API keys exist; settings come from environment/.env (git-ignored) | - |
| T12 | Denial of service | Bounded queries and exports | No rate limiting; SQLite single-writer |

## Explicitly out of scope / not claimed

- Real authentication, session management, MFA, or device attestation.
- Authorisation of the management API (anyone with network access can edit policies or read logs).
- Tamper-evident or signed audit logs; log retention/rotation.
- TLS termination, rate limiting, WAF, or multi-tenant isolation.
- A spoofing defence: a caller can claim any role, device trust or MFA state. That is the nature of the simulation.

## Hardening ideas for further study

Authenticated admin API, signed JWT identities from a real IdP, device posture from MDM, structured logging with hash chaining,
rate limiting, Postgres, and policy change approvals with versioning.
