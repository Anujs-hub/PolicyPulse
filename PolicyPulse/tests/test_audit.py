import csv
import io

import pytest

from tests.conftest import evaluate


def seed(client):
    evaluate(client, user_id="bob")
    evaluate(client, user_id="carol", role="employee", resource_id="finance-ledger", action="write")
    evaluate(client, user_id="alice", role="admin", resource_id="prod-admin-console", action="admin", mfa_verified=False)
    evaluate(client, user_id="bob", failed_logins=5)


def test_each_evaluation_is_persisted(client, db):
    from app.models.audit_log import AuditLog
    res = evaluate(client)
    row = db.query(AuditLog).filter_by(event_id=res["request_id"]).one()
    assert row.decision == "ALLOW" and row.user_id == "bob" and row.risk_score == res["risk_score"]
    assert row.matched_rules and row.explanation
    assert row.event_metadata["device_trust"] == "trusted" and row.event_metadata["simulated"] is True


def test_audit_listing_and_pagination(client):
    seed(client)
    d = client.get("/api/audit-logs", params={"page_size": 3}).json()
    assert d["total"] == 4 and d["pages"] == 2 and len(d["items"]) == 3 and d["page"] == 1
    d2 = client.get("/api/audit-logs", params={"page_size": 3, "page": 2}).json()
    assert len(d2["items"]) == 1
    assert client.get("/api/audit-logs", params={"page": 9, "page_size": 3}).json()["items"] == []
    ts = [i["timestamp"] for i in d["items"]]
    assert ts == sorted(ts, reverse=True)


def test_filters(client):
    seed(client)
    get = lambda **p: client.get("/api/audit-logs", params=p).json()
    assert get(decision="DENY")["total"] == 2
    assert get(decision="STEP_UP")["total"] == 1
    assert get(user_id="bob")["total"] == 2
    assert get(resource_id="finance-ledger")["total"] == 1
    assert get(q="prod-admin")["total"] == 1
    assert get(q="CAROL")["total"] == 1 or get(q="carol")["total"] == 1
    assert get(min_risk=50)["total"] == 1
    assert get(max_risk=20)["total"] == 1
    assert get(decision="DENY", user_id="bob")["total"] == 1
    assert get(q="no-such-thing")["total"] == 0
    assert get(date_from="2999-01-01T00:00:00Z")["total"] == 0
    assert get(date_to="2999-01-01T00:00:00Z")["total"] == 4


def test_search_treats_like_wildcards_literally(client):
    seed(client)
    assert client.get("/api/audit-logs", params={"q": "%"}).json()["total"] == 0
    assert client.get("/api/audit-logs", params={"q": "_"}).json()["total"] == 0


@pytest.mark.parametrize("params", [
    {"page": 0}, {"page_size": 0}, {"page_size": 101}, {"page_size": 100000}, {"decision": "MAYBE"},
    {"min_risk": -1}, {"max_risk": 101}, {"min_risk": 80, "max_risk": 10}, {"date_from": "garbage"},
    {"user_id": "bad id!"}, {"q": "x" * 101},
    {"date_from": "2030-01-01T00:00:00Z", "date_to": "2020-01-01T00:00:00Z"},
])
def test_invalid_audit_queries_rejected(client, params):
    assert client.get("/api/audit-logs", params=params).status_code == 422


def test_sql_injection_in_search_is_inert(client):
    seed(client)
    r = client.get("/api/audit-logs", params={"q": "' OR 1=1; DROP TABLE audit_logs;--"})
    assert r.status_code == 200 and r.json()["total"] == 0
    assert client.get("/api/audit-logs").json()["total"] == 4


def test_csv_export(client):
    seed(client)
    r = client.get("/api/audit-logs/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.reader(io.StringIO(r.text)))
    assert rows[0][:4] == ["event_id", "timestamp", "user_id", "role"]
    assert len(rows) == 5
    filtered = client.get("/api/audit-logs/export", params={"decision": "DENY"}).text
    assert len(list(csv.reader(io.StringIO(filtered)))) == 3


def test_csv_export_neutralises_formula_injection(client, db):
    from datetime import datetime, timezone
    from app.models.audit_log import AuditLog
    # '-' and '@' are legal leading characters for a user_id; '=' and '+' are rejected by validation.
    evaluate(client, user_id="-2")
    evaluate(client, user_id="@sum")
    # Defence in depth: rows that bypassed validation (e.g. imported data) are still neutralised on export.
    db.add(AuditLog(event_id="evil-1", timestamp=datetime.now(timezone.utc), user_id="=HYPERLINK(\"http://x\")",
                    role="analyst", resource_id="+cmd", action="read", decision="DENY", risk_score=1,
                    risk_level="low", matched_rules=[], explanation="=1+1", remediation=[], event_metadata={}))
    db.commit()
    rows = list(csv.reader(io.StringIO(client.get("/api/audit-logs/export").text)))[1:]
    assert len(rows) == 3
    for r in rows:
        for cell in (r[2], r[4], r[10]):
            assert not cell.startswith(("=", "+", "-", "@")) or cell.startswith("'")
    evil = next(r for r in rows if r[0] == "evil-1")
    assert evil[2].startswith("'=") and evil[4] == "'+cmd" and evil[10] == "'=1+1"
    assert {r[2] for r in rows if r[0] != "evil-1"} == {"'-2", "'@sum"}
    assert client.post("/api/evaluate", json={**__import__("tests.conftest", fromlist=["GOOD"]).GOOD, "user_id": "=cmd"}).status_code == 422


def test_csv_safe_helper():
    from app.services.audit_service import csv_safe
    assert csv_safe("=1+1") == "'=1+1" and csv_safe("+x") == "'+x" and csv_safe("-x") == "'-x"
    assert csv_safe("@x") == "'@x" and csv_safe("\tx") == "'\tx" and csv_safe("\rx") == "'\rx"
    assert csv_safe("normal") == "normal" and csv_safe(None) == "" and csv_safe(5) == "5"


def test_export_row_limit(settings):
    from fastapi.testclient import TestClient
    from app.main import create_app
    s = settings.model_copy(update={"export_max_rows": 2})
    with TestClient(create_app(s)) as c:
        for _ in range(4):
            evaluate(c)
        assert len(list(csv.reader(io.StringIO(c.get("/api/audit-logs/export").text)))) == 3
