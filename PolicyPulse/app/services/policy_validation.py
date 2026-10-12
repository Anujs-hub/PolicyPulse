"""Whitelist-based validation for policy conditions.

Policies are *data*: a list of ``{field, operator, value}`` triples that are
AND-ed together. Nothing is ever passed to ``eval``/``exec``; every field and
operator must appear in the whitelists below.
"""
from typing import Any, Dict, List

from app.services.catalog import (
    RESOURCES, SENSITIVITY_LEVEL, AccessContext, Action, DeviceTrust, Role, Sensitivity,
)

ENUM_OPS = {"eq", "neq", "in", "not_in"}
BOOL_OPS = {"eq", "neq"}
INT_OPS = {"eq", "neq", "gt", "gte", "lt", "lte"}
MAX_CONDITIONS = 8
MAX_LIST_ITEMS = 10

FIELD_SPECS: Dict[str, dict] = {
    "role": {"type": "enum", "values": [r.value for r in Role]},
    "action": {"type": "enum", "values": [a.value for a in Action]},
    "resource_id": {"type": "enum", "values": list(RESOURCES)},
    "resource_sensitivity": {"type": "enum", "values": [s.value for s in Sensitivity]},
    "sensitivity_level": {"type": "int", "min": 1, "max": 4},
    "device_trust": {"type": "enum", "values": [d.value for d in DeviceTrust]},
    "mfa_verified": {"type": "bool"},
    "failed_logins": {"type": "int", "min": 0, "max": 100},
    "access_context": {"type": "enum", "values": [c.value for c in AccessContext]},
    "risk_score": {"type": "int", "min": 0, "max": 100},
    "rbac_permitted": {"type": "bool"},
}
OPERATORS = sorted(ENUM_OPS | BOOL_OPS | INT_OPS)
EFFECTS = ("ALLOW", "DENY", "STEP_UP")


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def validate_condition(cond: Any) -> Dict[str, Any]:
    """Validate and normalise one condition. Raises ValueError with a clear message."""
    if not isinstance(cond, dict):
        raise ValueError("condition must be an object with field, operator and value")
    extra = set(cond) - {"field", "operator", "value"}
    if extra:
        raise ValueError(f"unexpected keys in condition: {sorted(extra)}")
    field, op, value = cond.get("field"), cond.get("operator"), cond.get("value")
    spec = FIELD_SPECS.get(field) if isinstance(field, str) else None
    if spec is None:
        raise ValueError(f"unknown field {field!r}; allowed: {sorted(FIELD_SPECS)}")
    ftype = spec["type"]
    allowed_ops = {"enum": ENUM_OPS, "bool": BOOL_OPS, "int": INT_OPS}[ftype]
    if op not in allowed_ops:
        raise ValueError(f"operator {op!r} is not valid for {field!r}; allowed: {sorted(allowed_ops)}")

    if ftype == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{field!r} requires a boolean value")
    elif ftype == "int":
        if not _is_int(value) or not (spec["min"] <= value <= spec["max"]):
            raise ValueError(f"{field!r} requires an integer between {spec['min']} and {spec['max']}")
    else:
        if op in ("in", "not_in"):
            if not isinstance(value, list) or not value or len(value) > MAX_LIST_ITEMS:
                raise ValueError(f"operator {op!r} requires a non-empty list (max {MAX_LIST_ITEMS} items)")
            bad = [v for v in value if v not in spec["values"]]
            if bad:
                raise ValueError(f"invalid values for {field!r}: {bad}; allowed: {spec['values']}")
        elif value not in spec["values"] or not isinstance(value, str):
            raise ValueError(f"invalid value {value!r} for {field!r}; allowed: {spec['values']}")
    return {"field": field, "operator": op, "value": value}


def validate_policy_definition(conditions: Any, effect: str) -> List[Dict[str, Any]]:
    if not isinstance(conditions, list) or not conditions:
        raise ValueError("a policy needs at least one condition")
    if len(conditions) > MAX_CONDITIONS:
        raise ValueError(f"at most {MAX_CONDITIONS} conditions are allowed")
    if effect not in EFFECTS:
        raise ValueError(f"effect must be one of {list(EFFECTS)}")
    normalised = [validate_condition(c) for c in conditions]
    if effect == "ALLOW":
        # Least privilege: an ALLOW can never apply to a request RBAC rejects.
        if not any(c["field"] == "rbac_permitted" and c["operator"] == "eq" and c["value"] is True
                   for c in normalised):
            raise ValueError("ALLOW policies must include the condition rbac_permitted eq true")
    return normalised


def sensitivity_level_of(name: str) -> int:
    return SENSITIVITY_LEVEL.get(name, 4)
