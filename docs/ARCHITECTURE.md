# Architecture

PolicyPulse is a single-process FastAPI application with a SQLite database and a server-rendered, JavaScript-enhanced UI.

## Layers

| Layer | Modules | Responsibility |
|---|---|---|
| Transport | `app/main.py`, `app/api/routes.py`, `app/api/pages.py` | HTTP, routing, query validation, middleware, error shaping |
| Schemas | `app/schemas/*` | Pydantic models for requests/responses (strict, `extra="forbid"` on input) |
| Domain / services | `app/services/*` | Policy evaluation, risk scoring, validation, audit, catalog |
| Persistence | `app/models/*`, `app/database.py` | SQLAlchemy ORM models, engine/session management, seeding |
| Presentation | `app/templates`, `app/static` | Jinja2 shells; JavaScript fetches JSON and builds DOM with `textContent` |

The **policy engine is a pure function** (`evaluate(AccessInput, rules) -> EngineDecision`). It never touches the
database or HTTP, which makes it deterministic and easy to test; `policy_service.load_rules` and
`audit_service.record_evaluation` wrap it with persistence.

## Application factory

`create_app(settings)` builds an engine, session factory and FastAPI app from a `Settings` object. Tests pass a
temporary database URL; production code uses the module-level `app` (built lazily on first access so importing the
module has no side effects). `lifespan` runs `init_db`: create tables, then seed any missing default policies
(matched by `code`, so restarts never duplicate them).

## Middleware (in `main.py`)

- CORS: explicit origin list, no credentials, methods GET/POST/PATCH/DELETE/OPTIONS.
- Request-size guard: rejects `Content-Length` above `POLICYPULSE_MAX_REQUEST_BYTES` with 413.
- Security headers: `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, a strict
  `Content-Security-Policy` (everything `'self'`; skipped for `/docs`, `/redoc`, `/openapi.json`), and `Cache-Control: no-store` for API responses.
- Exception handlers: 422 bodies contain only `loc`/`msg`/`type`; unhandled errors return `{"detail": "Internal server error", "error_id": ...}`
  and log the stack trace server-side only.

## Data model

- `policies`: `id, code (unique), name (unique), description, conditions (JSON), effect, priority, enabled, mandatory, remediation, created_at, updated_at`
- `audit_logs`: `id, event_id (UUID, unique), timestamp, user_id, role, resource_id, action, decision, risk_score, risk_level, matched_rules (JSON), explanation, remediation (JSON), metadata (JSON)`

The audit `metadata` JSON stores device trust, MFA flag, failed logins, access context, resource sensitivity, RBAC result,
the risk-factor breakdown, skipped (malformed) rules and the engine version. Timestamps are stored in UTC.

## Frontend

Pages: Dashboard (`/`), Simulator (`/simulator`), Policies (`/policies`), Audit logs (`/audit`).
`static/js/common.js` provides `PP.el` (safe DOM builder), `PP.api` (fetch + error parsing), toasts and nav toggling.
Chart.js 4.4.7 is vendored so the dashboard works offline. No inline scripts or inline `style` attributes are used, which keeps the CSP strict.
