import pytest

from tests.conftest import evaluate

NEW = {"name": "Step up for HR writes", "description": "demo", "effect": "STEP_UP", "priority": 150,
       "conditions": [{"field": "resource_id", "operator": "eq", "value": "hr-portal"},
                      {"field": "action", "operator": "eq", "value": "write"},
                      {"field": "mfa_verified", "operator": "eq", "value": False}],
       "remediation": "Complete MFA."}


def test_default_policies_are_seeded_and_listed(client):
    r = client.get("/api/policies")
    assert r.status_code == 200
    pols = r.json()
    codes = {p["code"] for p in pols}
    assert {"P-001", "P-002", "P-201"} <= codes
    assert all(p["enabled"] for p in pols)
    assert [p["priority"] for p in pols] == sorted(p["priority"] for p in pols)
    assert {p["code"] for p in pols if p["mandatory"]} == {"P-001", "P-002"}


def test_create_policy_and_it_takes_effect(client):
    r = client.post("/api/policies", json=NEW)
    assert r.status_code == 201
    created = r.json()
    assert created["code"].startswith("CUST-") and created["mandatory"] is False
    assert client.get(f"/api/policies/{created['id']}").json()["name"] == NEW["name"]
    res = evaluate(client, user_id="alice", role="admin", resource_id="hr-portal", action="write", mfa_verified=False)
    assert res["decision"] == "STEP_UP" and created["code"] in [m["code"] for m in res["matched_rules"]]


def test_duplicate_name_conflicts(client):
    assert client.post("/api/policies", json=NEW).status_code == 201
    assert client.post("/api/policies", json=NEW).status_code == 409


@pytest.mark.parametrize("mutate", [
    lambda p: p.update(effect="MAYBE"),
    lambda p: p.update(name="x"),
    lambda p: p.update(priority=0),
    lambda p: p.update(priority=1001),
    lambda p: p.update(conditions=[]),
    lambda p: p.update(conditions=[{"field": "password", "operator": "eq", "value": "x"}]),
    lambda p: p.update(conditions=[{"field": "risk_score", "operator": "eval", "value": 1}]),
    lambda p: p.update(conditions=[{"field": "risk_score", "operator": "gte", "value": "__import__('os').system('id')"}]),
    lambda p: p.update(conditions=[{"field": "risk_score > 5 or True", "operator": "eq", "value": 1}]),
    lambda p: p.update(mandatory=True),
    lambda p: p.update(code="P-001"),
    lambda p: p.update(effect="ALLOW"),  # ALLOW without rbac_permitted condition
])
def test_unsafe_or_invalid_policies_are_rejected(client, mutate):
    payload = {**NEW, "conditions": list(NEW["conditions"])}
    mutate(payload)
    r = client.post("/api/policies", json=payload)
    assert r.status_code == 422, r.text
    assert len(client.get("/api/policies").json()) == 11  # nothing was stored


def test_update_policy_fields_and_disable(client):
    pid = client.post("/api/policies", json=NEW).json()["id"]
    r = client.patch(f"/api/policies/{pid}", json={"priority": 160, "enabled": False, "description": "changed"})
    assert r.status_code == 200
    body = r.json()
    assert body["priority"] == 160 and body["enabled"] is False and body["description"] == "changed"
    res = evaluate(client, user_id="alice", role="admin", resource_id="hr-portal", action="write", mfa_verified=False)
    assert body["code"] not in [m["code"] for m in res["matched_rules"]]


def test_update_validates_merged_definition(client):
    pid = client.post("/api/policies", json=NEW).json()["id"]
    assert client.patch(f"/api/policies/{pid}", json={"effect": "ALLOW"}).status_code == 422
    assert client.patch(f"/api/policies/{pid}", json={}).status_code == 422
    assert client.patch(f"/api/policies/{pid}", json={"conditions": [{"field": "x", "operator": "eq", "value": 1}]}).status_code == 422
    assert client.patch(f"/api/policies/{pid}", json={"name": "P-001 clash", "bogus": 1}).status_code == 422


def test_update_name_conflict_and_missing_policy(client):
    pid = client.post("/api/policies", json=NEW).json()["id"]
    assert client.patch(f"/api/policies/{pid}", json={"name": "Block excessive failed logins"}).status_code == 409
    assert client.patch("/api/policies/99999", json={"enabled": False}).status_code == 404
    assert client.get("/api/policies/99999").status_code == 404
    assert client.delete("/api/policies/99999").status_code == 404


def test_mandatory_policy_text_can_be_edited_but_not_logic(client):
    p1 = next(p for p in client.get("/api/policies").json() if p["code"] == "P-001")
    ok = client.patch(f"/api/policies/{p1['id']}", json={"description": "Updated text"})
    assert ok.status_code == 200 and ok.json()["description"] == "Updated text"
    assert client.patch(f"/api/policies/{p1['id']}", json={"enabled": False}).status_code == 403


def test_delete_non_mandatory_policy(client):
    pid = client.post("/api/policies", json=NEW).json()["id"]
    assert client.delete(f"/api/policies/{pid}").status_code == 204
    assert client.get(f"/api/policies/{pid}").status_code == 404


def test_disabling_optional_policy_changes_outcome(client):
    base = dict(user_id="alice", role="admin", resource_id="hr-portal", action="write", mfa_verified=False)
    assert evaluate(client, **base)["decision"] == "STEP_UP"
    p101 = next(p for p in client.get("/api/policies").json() if p["code"] == "P-101")
    assert client.patch(f"/api/policies/{p101['id']}", json={"enabled": False}).status_code == 200
    # Still ALLOW-able only if other rules permit: risk=20+... P-201 allows (risk 35 <= 49).
    assert evaluate(client, **base)["decision"] == "ALLOW"
