import sqlite3

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.conftest import GOOD, evaluate


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.json()["database"] == "ok"


def test_dashboard_empty(client):
    d = client.get("/api/dashboard").json()
    assert d["total_requests"] == 0 and d["recent_decisions"] == []
    assert [b["label"] for b in d["risk_distribution"]] == ["0-19", "20-39", "40-59", "60-79", "80-100"]
    assert len(d["timeline"]) == 7


def test_dashboard_counts(client):
    evaluate(client)                                   # ALLOW, risk 10
    evaluate(client, failed_logins=5)                  # DENY, risk 35
    evaluate(client, user_id="alice", role="admin", resource_id="prod-admin-console", action="admin", mfa_verified=False)  # STEP_UP 60
    d = client.get("/api/dashboard").json()
    assert (d["total_requests"], d["allowed"], d["denied"], d["step_up"]) == (3, 1, 1, 1)
    buckets = {b["label"]: b["count"] for b in d["risk_distribution"]}
    assert buckets["0-19"] == 1 and buckets["20-39"] == 1 and buckets["60-79"] == 1
    assert sum(buckets.values()) == 3
    assert len(d["recent_decisions"]) == 3
    assert any(p["code"] == "P-001" and p["hits"] == 1 for p in d["policy_activity"])
    today = d["timeline"][-1]
    assert today["ALLOW"] + today["DENY"] + today["STEP_UP"] == 3


def test_database_initialisation_is_idempotent_and_isolated(tmp_path):
    db_file = tmp_path / "fresh.db"
    for _ in range(2):  # starting twice must not duplicate the seeded policies
        with TestClient(create_app(Settings(database_url=f"sqlite:///{db_file}", _env_file=None))) as c:
            assert len(c.get("/api/policies").json()) == 11
    tables = {r[0] for r in sqlite3.connect(db_file).execute("select name from sqlite_master where type='table'")}
    assert {"policies", "audit_logs"} <= tables


def test_tests_use_isolated_databases(settings, client):
    assert "test.db" in settings.database_url and "policypulse.db" not in settings.database_url


def test_pages_render_and_assets_exist(client):
    for path in ("/", "/simulator", "/policies", "/audit"):
        r = client.get(path)
        assert r.status_code == 200 and "text/html" in r.headers["content-type"]
        assert "Educational" in r.text or "Simulation only" in r.text
    for asset in ("css/style.css", "js/common.js", "js/dashboard.js", "js/simulator.js", "js/policies.js",
                  "js/audit.js", "vendor/chart.umd.js"):
        assert client.get(f"/static/{asset}").status_code == 200, asset


def test_templates_reference_existing_static_files(client):
    import re
    for path in ("/", "/simulator", "/policies", "/audit"):
        for src in re.findall(r'(?:src|href)="(/static/[^"]+)"', client.get(path).text):
            assert client.get(src).status_code == 200, src


def test_catalog_and_scenarios_endpoints(client):
    c = client.get("/api/catalog").json()
    assert set(c["roles"]) == {"admin", "analyst", "employee"} and len(c["resources"]) >= 5
    assert len(client.get("/api/scenarios").json()) == 5


def test_openapi_docs_available(client):
    assert client.get("/docs").status_code == 200
    paths = client.get("/openapi.json").json()["paths"]
    for p in ("/health", "/api/dashboard", "/api/evaluate", "/api/policies", "/api/policies/{policy_id}",
              "/api/audit-logs", "/api/audit-logs/export"):
        assert p in paths


def test_request_size_limit(client):
    big = {**GOOD, "user_id": "a" * 70000}
    r = client.post("/api/evaluate", json=big)
    assert r.status_code == 413


def test_security_headers(client):
    r = client.get("/")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert client.get("/api/policies").headers["cache-control"] == "no-store"


def test_cors_allows_only_configured_origins(client):
    ok = client.get("/health", headers={"Origin": "http://localhost:8000"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:8000"
    bad = client.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in bad.headers


def test_unknown_route_returns_json_404(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.json() == {"detail": "Not Found"}


def test_unhandled_errors_do_not_leak_details(settings, monkeypatch):
    app = create_app(settings)
    import app.api.routes as routes

    def boom(*a, **k):
        raise RuntimeError("secret-internal-detail /etc/passwd")
    monkeypatch.setattr(routes.policy_service, "list_policies", boom)
    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/api/policies")
    assert r.status_code == 500
    assert "secret-internal-detail" not in r.text and "Traceback" not in r.text
    assert r.json()["detail"] == "Internal server error"
