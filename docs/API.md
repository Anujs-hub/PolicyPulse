# REST API

Base URL: `http://127.0.0.1:8000`. Interactive docs: `/docs` (Swagger UI) and `/redoc`; schema at `/openapi.json`.
There is **no authentication** (educational prototype). All bodies are JSON. Errors use `{"detail": ...}`.

## Status codes

| Code | Meaning |
|---|---|
| 200 / 201 / 204 | OK / policy created / policy deleted |
| 403 | Mandatory policy cannot be changed or deleted |
| 404 | Policy not found |
| 409 | Policy name already exists |
| 413 | Request body larger than `POLICYPULSE_MAX_REQUEST_BYTES` |
| 422 | Validation error. `detail` is a list of `{loc, msg, type}` (or a string for cross-field checks) |
| 500 | `{"detail": "Internal server error", "error_id": "..."}` (no stack trace) |

## Endpoints

### `GET /health`
`{"status":"ok","version":"1.0.0","database":"ok"}`

### `POST /api/evaluate`
Evaluate a simulated request and store an audit event.

Request:
```json
{"user_id":"alice","role":"admin","resource_id":"prod-admin-console","action":"admin",
 "device_trust":"trusted","mfa_verified":false,"failed_logins":0,"access_context":"normal"}
```
Response (abridged):
```json
{"request_id":"<uuid>","timestamp":"2026-01-01T10:00:00Z","decision":"STEP_UP","risk_score":60,"risk_level":"high",
 "risk_factors":[{"factor":"resource_sensitivity","value":"critical","points":30}, "..."],
 "matched_rules":[{"code":"P-101","name":"...","effect":"STEP_UP","priority":100,"mandatory":false,"decisive":true,"system":false}],
 "explanation":"Request by alice (admin) for admin on 'prod-admin-console' ...",
 "remediation":["Complete multi-factor authentication, then resubmit the request."],
 "disclaimer":"Educational simulation: ..."}
```

### `GET /api/dashboard`
`total_requests, allowed, denied, step_up, risk_distribution[], policy_activity[], timeline[7 days], recent_decisions[10], activity_window`.

### Policies
| Method | Path | Notes |
|---|---|---|
| GET | `/api/policies` | sorted by priority |
| GET | `/api/policies/{id}` | |
| POST | `/api/policies` | body: `name, description?, conditions[], effect, priority?(1-1000, default 300), enabled?, remediation?` -> 201 |
| PATCH | `/api/policies/{id}` | any subset of the create fields; validated as a merged policy. Mandatory policies: only `description`, `remediation` |
| DELETE | `/api/policies/{id}` | non-mandatory only -> 204 |

Condition: `{"field": "...", "operator": "...", "value": ...}`. See [POLICY_MODEL.md](POLICY_MODEL.md) for the whitelist.

### `GET /api/audit-logs`
Query parameters: `page` (>=1, default 1), `page_size` (1-`MAX_PAGE_SIZE`, default 20, max 100), `q` (<=100 chars; matches user, resource, event ID, explanation),
`decision` (`ALLOW|DENY|STEP_UP`), `user_id`, `resource_id`, `min_risk`, `max_risk` (0-100), `date_from`, `date_to` (ISO 8601; naive values are treated as UTC).
Response: `{items[], total, page, page_size, pages}`; items are newest first. Each item has `event_id, timestamp, user_id, role, resource_id, action, decision, risk_score, risk_level, matched_rules, explanation, remediation, event_metadata`.

### `GET /api/audit-logs/export`
Same filters (no pagination). Returns `text/csv` as an attachment, newest first, at most `POLICYPULSE_EXPORT_MAX_ROWS` rows.
Columns: `event_id, timestamp, user_id, role, resource_id, action, decision, risk_score, risk_level, matched_rules, explanation, remediation, metadata`.
All fields are quoted and cells beginning with `= + - @ TAB CR` get a leading `'`.

### Reference endpoints (used by the UI)
- `GET /api/catalog` - roles, actions, resources with permissions, enums, policy field whitelist.
- `GET /api/scenarios` - the five sample scenarios with expected decisions.
