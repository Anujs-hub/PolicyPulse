import pytest

from app.services.policy_validation import validate_condition, validate_policy_definition

OK = {"field": "risk_score", "operator": "gte", "value": 50}


def test_valid_condition_is_normalised():
    assert validate_condition(dict(OK)) == OK


@pytest.mark.parametrize("bad", [
    {"field": "password", "operator": "eq", "value": 1},
    {"field": "risk_score", "operator": "matches", "value": 1},
    {"field": "risk_score", "operator": "gte", "value": "50"},
    {"field": "risk_score", "operator": "gte", "value": 101},
    {"field": "risk_score", "operator": "gte", "value": True},
    {"field": "mfa_verified", "operator": "eq", "value": "true"},
    {"field": "mfa_verified", "operator": "gt", "value": True},
    {"field": "role", "operator": "eq", "value": "root"},
    {"field": "role", "operator": "in", "value": []},
    {"field": "role", "operator": "in", "value": ["admin", "root"]},
    {"field": "risk_score", "operator": "gte", "value": 5, "extra": 1},
    {"field": "__import__('os')", "operator": "eq", "value": 1},
    {"field": "risk_score", "operator": "gte", "value": "__import__('os').system('id')"},
    "risk_score > 5",
])
def test_invalid_conditions_rejected(bad):
    with pytest.raises(ValueError):
        validate_condition(bad)


def test_allow_policy_requires_rbac_condition():
    with pytest.raises(ValueError, match="rbac_permitted"):
        validate_policy_definition([OK], "ALLOW")
    ok = validate_policy_definition([OK, {"field": "rbac_permitted", "operator": "eq", "value": True}], "ALLOW")
    assert len(ok) == 2


def test_condition_count_and_effect_limits():
    with pytest.raises(ValueError):
        validate_policy_definition([], "DENY")
    with pytest.raises(ValueError):
        validate_policy_definition([OK] * 9, "DENY")
    with pytest.raises(ValueError):
        validate_policy_definition([OK], "MAYBE")
