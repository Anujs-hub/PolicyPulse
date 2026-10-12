# Testing

```powershell
python -m pytest            # whole suite
python -m pytest -v         # verbose
python -m pytest -k mandatory
```

## Isolation and determinism

- The `client` fixture (`tests/conftest.py`) builds a fresh app with `sqlite:///<pytest tmp_path>/test.db` for every test; `data/policypulse.db` is never touched.
- `Settings(..., _env_file=None)` prevents a developer's `.env` from changing test behaviour.
- No network access, no clocks asserted to the second, no randomness. The engine is pure and deterministic.

## Coverage map

| Requirement | Test module(s) |
|---|---|
| All three decision outcomes | `test_policy_engine.py`, `test_api_evaluate.py` (incl. the five sample scenarios) |
| Role and resource authorisation | `test_policy_engine.py::test_rbac_matrix_is_enforced_for_every_combination` (3 roles x 7 resources x 4 actions), `test_api_evaluate.py` |
| Policy precedence | `test_policy_engine.py` (severity beats priority; priority orders within an effect) |
| Mandatory deny enforcement | `test_policy_engine.py`, `test_api_evaluate.py` (API cannot disable/shadow; DB tampering still denied), `test_policies_api.py` |
| Risk scoring boundaries | `test_risk_scoring.py` (levels 29/30, 59/60, 79/80; caps; per-factor points) |
| Invalid request data | `test_api_evaluate.py`, `test_policy_validation.py`, `test_policies_api.py`, `test_audit.py` |
| Audit persistence and filtering | `test_audit.py` |
| Policy creation and updates | `test_policies_api.py` |
| Health and dashboard | `test_system.py` |
| CSV export and formula injection | `test_audit.py` |
| Database initialisation | `test_system.py` (idempotent seeding, tables present) |
| Security behaviours | `test_system.py` (size limit, headers, CORS, generic 500) |

## What is not covered

- The browser UI is not exercised by automated browser tests. `test_system.py` checks that pages render and that every `/static/...` file they reference is served; JavaScript syntax was checked with `node --check` during packaging, but UI behaviour should be verified manually (open each page and run the five scenarios).
- Docker artifacts are not tested by the suite.
- No load or fuzz testing.
