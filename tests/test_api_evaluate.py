import pytest

from app.services.scenarios import SCENARIOS
from tests.conftest import GOOD, evaluate


def test_allow_deny_step_up_via_api(client):
    assert evaluate(client)["decision"] == "ALLOW"
    assert evaluate(client, resource_id="customer-db", device_trust="untrusted")["decision"] == "DENY"
    r = evaluate(client, user_id="alice", role="admin", resource_id="prod-admin-console", action="admin", mfa_verified=False)
    assert r["decision"] == "STEP_UP"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_sample_scenarios_produce_documented_decisions(client, scenario):
    r = client.post("/api/evaluate", json=scenario["request"]).json()
    assert r["decision"] == scenario["expected_decision"]


def test_response_is_explainable(client):
    r = evaluate(client, failed_logins=5)
    assert r["decision"] == "DENY"
    assert r["request_id"] and len(r["request_id"]) == 36
    assert r["timestamp"] and r["explanation"] and r["remediation"]
    assert any(m["code"] == "P-001" and m["mandatory"] and m["decisive"] for m in r["matched_rules"])
    assert r["risk_factors"] and "disclaimer" in r


def test_request_ids_are_unique(client):
    assert evaluate(client)["request_id"] != evaluate(client)["request_id"]


def test_employee_cannot_access_admin_resources(client):
    for res in ("prod-admin-console", "secrets-vault", "finance-ledger", "customer-db"):
        r = evaluate(client, user_id="carol", role="employee", resource_id=res)
        assert r["decision"] == "DENY"
        assert r["matched_rules"][0]["code"] == "SYS-RBAC"


def test_least_privilege_analyst_cannot_write_customer_db(client):
    assert evaluate(client, resource_id="customer-db", action="read")["decision"] == "ALLOW"
    assert evaluate(client, resource_id="customer-db", action="write")["decision"] == "DENY"


@pytest.mark.parametrize("override", [
    {"role": "root"}, {"action": "execute"}, {"device_trust": "super"}, {"access_context": "mars"},
    {"resource_id": "nope"}, {"user_id": ""}, {"user_id": "a b"}, {"user_id": "x" * 65},
    {"user_id": "<script>"}, {"user_id": "'; DROP TABLE audit_logs;--"},
    {"failed_logins": -1}, {"failed_logins": 101}, {"failed_logins": "3"}, {"failed_logins": 1.5},
    {"mfa_verified": "yes"}, {"mfa_verified": 1}, {"mfa_verified": None}, {"unexpected": 1},
])
def test_invalid_request_data_is_rejected(client, override):
    r = client.post("/api/evaluate", json={**GOOD, **override})
    assert r.status_code == 422
    body = r.json()
    assert isinstance(body["detail"], list) and "Traceback" not in r.text


def test_missing_fields_rejected(client):
    assert client.post("/api/evaluate", json={"user_id": "bob"}).status_code == 422
    assert client.post("/api/evaluate", content=b"not json", headers={"content-type": "application/json"}).status_code == 422
    assert client.post("/api/evaluate", json=[1, 2]).status_code == 422


def test_invalid_requests_are_not_audited(client):
    client.post("/api/evaluate", json={**GOOD, "role": "root"})
    assert client.get("/api/audit-logs").json()["total"] == 0


def test_mandatory_deny_cannot_be_bypassed_via_api(client):
    # Attempt 1: try to disable/lower every mandatory rule through the API.
    pols = client.get("/api/policies").json()
    for p in (p for p in pols if p["mandatory"]):
        assert client.patch(f"/api/policies/{p['id']}", json={"enabled": False}).status_code == 403
        assert client.patch(f"/api/policies/{p['id']}", json={"priority": 1000}).status_code == 403
        assert client.patch(f"/api/policies/{p['id']}", json={"effect": "ALLOW"}).status_code == 403
        assert client.delete(f"/api/policies/{p['id']}").status_code == 403
    # Attempt 2: create an all-powerful ALLOW policy at priority 1.
    r = client.post("/api/policies", json={
        "name": "Allow everything", "effect": "ALLOW", "priority": 1,
        "conditions": [{"field": "rbac_permitted", "operator": "eq", "value": True}]})
    assert r.status_code == 201
    assert evaluate(client, failed_logins=5)["decision"] == "DENY"
    assert evaluate(client, resource_id="customer-db", device_trust="untrusted")["decision"] == "DENY"


def test_mandatory_deny_enforced_even_if_database_row_is_tampered(client, db):
    from app.models.policy import Policy
    for p in db.query(Policy).filter(Policy.mandatory.is_(True)).all():
        p.enabled = False
    db.commit()
    assert evaluate(client, failed_logins=7)["decision"] == "DENY"
