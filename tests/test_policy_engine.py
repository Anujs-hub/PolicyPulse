"""Pure engine tests: no database, no HTTP."""
import dataclasses

import pytest

from app.services import catalog
from app.services.default_policies import DEFAULT_POLICIES
from app.services.policy_engine import AccessInput, PolicyRule, evaluate


def default_rules():
    return [PolicyRule(code=p["code"], name=p["name"], description=p["description"], conditions=p["conditions"],
                       effect=p["effect"], priority=p["priority"], enabled=True, mandatory=p["mandatory"],
                       remediation=p["remediation"]) for p in DEFAULT_POLICIES]


BASE = AccessInput("bob", "analyst", "siem-dashboard", "read", "trusted", True, 0, "normal")


def inp(**kw):
    return dataclasses.replace(BASE, **kw)


def codes(result):
    return [m.code for m in result.matched_rules]


def test_allow_outcome():
    r = evaluate(BASE, default_rules())
    assert r.decision == "ALLOW" and "P-201" in codes(r)
    assert r.remediation and r.explanation


def test_deny_outcome_for_untrusted_sensitive():
    r = evaluate(inp(resource_id="customer-db", device_trust="untrusted"), default_rules())
    assert r.decision == "DENY" and "P-002" in codes(r)


def test_step_up_outcome_for_missing_mfa_on_privileged_action():
    r = evaluate(inp(role="admin", resource_id="prod-admin-console", action="admin", mfa_verified=False), default_rules())
    assert r.decision == "STEP_UP" and r.risk_score == 60
    assert {"P-101", "P-102", "P-105"} <= set(codes(r))


def test_rbac_denies_with_system_rule_even_without_policies():
    r = evaluate(inp(role="employee", resource_id="finance-ledger", action="write"), [])
    assert r.decision == "DENY" and codes(r)[0] == "SYS-RBAC"


@pytest.mark.parametrize("role", [r.value for r in catalog.Role])
@pytest.mark.parametrize("resource_id", list(catalog.RESOURCES))
@pytest.mark.parametrize("action", [a.value for a in catalog.Action])
def test_rbac_matrix_is_enforced_for_every_combination(role, resource_id, action):
    r = evaluate(inp(role=role, resource_id=resource_id, action=action), default_rules())
    if not catalog.is_permitted(role, resource_id, action):
        assert r.decision == "DENY" and "SYS-RBAC" in codes(r)
    else:
        assert "SYS-RBAC" not in codes(r)


def test_no_matching_policy_denies_by_default():
    r = evaluate(BASE, [])
    assert r.decision == "DENY" and "SYS-DEFAULT-DENY" in codes(r)


def test_allow_with_priority_one_cannot_override_mandatory_deny():
    sneaky = PolicyRule("X-1", "Allow everything", "", [{"field": "rbac_permitted", "operator": "eq", "value": True}],
                        "ALLOW", 1)
    r = evaluate(inp(failed_logins=5), default_rules() + [sneaky])
    assert r.decision == "DENY"
    assert {"P-001", "X-1"} <= set(codes(r))
    decisive = [m.code for m in r.matched_rules if m.decisive]
    assert "P-001" in decisive and "X-1" not in decisive


def test_deny_beats_step_up_and_step_up_beats_allow_regardless_of_priority():
    allow = PolicyRule("A", "allow", "", [{"field": "rbac_permitted", "operator": "eq", "value": True}], "ALLOW", 1)
    step = PolicyRule("S", "step", "", [{"field": "rbac_permitted", "operator": "eq", "value": True}], "STEP_UP", 900)
    deny = PolicyRule("D", "deny", "", [{"field": "rbac_permitted", "operator": "eq", "value": True}], "DENY", 999)
    assert evaluate(BASE, [allow]).decision == "ALLOW"
    assert evaluate(BASE, [allow, step]).decision == "STEP_UP"
    assert evaluate(BASE, [allow, step, deny]).decision == "DENY"


def test_priority_orders_rules_within_same_effect():
    a = PolicyRule("A", "a", "", [{"field": "rbac_permitted", "operator": "eq", "value": True}], "DENY", 50)
    b = PolicyRule("B", "b", "", [{"field": "rbac_permitted", "operator": "eq", "value": True}], "DENY", 20)
    r = evaluate(BASE, [a, b])
    assert [m.code for m in r.matched_rules][:2] == ["B", "A"]


def test_mandatory_policy_is_enforced_even_if_flagged_disabled():
    rules = [dataclasses.replace(r, enabled=False) if r.mandatory else r for r in default_rules()]
    assert evaluate(inp(failed_logins=9), rules).decision == "DENY"


def test_disabled_optional_policy_is_ignored():
    rules = [dataclasses.replace(r, enabled=False) if r.code == "P-101" else r for r in default_rules()]
    base = inp(role="admin", resource_id="hr-portal", action="write", mfa_verified=False)
    assert "P-101" in codes(evaluate(base, default_rules()))
    assert "P-101" not in codes(evaluate(base, rules))


def test_malformed_rule_is_skipped_not_executed():
    bad = PolicyRule("BAD", "bad", "", [{"field": "__import__('os').system('x')", "operator": "eq", "value": 1}], "ALLOW", 1)
    r = evaluate(BASE, default_rules() + [bad])
    assert "BAD" in r.skipped_rules and "BAD" not in codes(r)
    assert r.decision == "ALLOW"


def test_unknown_resource_fails_closed():
    r = evaluate(inp(resource_id="does-not-exist"), default_rules())
    assert r.decision == "DENY"


def test_evaluation_is_deterministic():
    a = evaluate(inp(failed_logins=3, mfa_verified=False), default_rules())
    b = evaluate(inp(failed_logins=3, mfa_verified=False), default_rules())
    assert (a.decision, a.risk_score, codes(a), a.explanation) == (b.decision, b.risk_score, codes(b), b.explanation)
