"""Deterministic, explainable policy engine (pure functions - no database access).

PRECEDENCE (explicit and total)
-------------------------------
1. System rule ``SYS-RBAC`` (priority 0, mandatory): if the role lacks the
   permission for the resource/action the result is DENY. It is hard-coded,
   not stored in the database and cannot be disabled.
2. Mandatory policies are always evaluated, even if their ``enabled`` flag was
   tampered with. Optional policies are evaluated only when enabled.
3. Decisions are resolved by *effect severity*, not by priority:
       any matched DENY  >  any matched STEP_UP  >  any matched ALLOW
   Therefore an ALLOW rule - whatever its priority number - can never override a
   DENY (mandatory or not) or a STEP_UP.
4. Priority (lower number = higher precedence) orders rules within the same
   effect; the first one is reported as the *primary* rule.
5. Fail closed: if nothing matched with ALLOW/STEP_UP/DENY the engine returns
   DENY via ``SYS-DEFAULT-DENY``.

Conditions are plain data validated by ``policy_validation``; no user-supplied
code is ever executed.
"""
import operator as _op
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from app.services import catalog
from app.services.risk_scoring import RiskFactor, compute_risk

ENGINE_VERSION = "1.0"

_COMPARATORS = {
    "eq": _op.eq, "neq": _op.ne, "gt": _op.gt, "gte": _op.ge, "lt": _op.lt, "lte": _op.le,
    "in": lambda a, b: a in b, "not_in": lambda a, b: a not in b,
}
_SEVERITY = {"DENY": 3, "STEP_UP": 2, "ALLOW": 1}


@dataclass(frozen=True)
class PolicyRule:
    code: str
    name: str
    description: str
    conditions: List[Dict[str, Any]]
    effect: str
    priority: int
    enabled: bool = True
    mandatory: bool = False
    remediation: str = ""


@dataclass(frozen=True)
class AccessInput:
    user_id: str
    role: str
    resource_id: str
    action: str
    device_trust: str
    mfa_verified: bool
    failed_logins: int
    access_context: str


@dataclass
class MatchedRule:
    code: str
    name: str
    effect: str
    priority: int
    mandatory: bool
    decisive: bool = False
    system: bool = False

    def as_dict(self) -> dict:
        return dict(self.__dict__)


@dataclass
class EngineDecision:
    decision: str
    risk_score: int
    risk_level: str
    risk_factors: List[RiskFactor]
    matched_rules: List[MatchedRule]
    explanation: str
    remediation: List[str]
    context: Dict[str, Any] = field(default_factory=dict)
    skipped_rules: List[str] = field(default_factory=list)


def build_context(inp: AccessInput) -> Dict[str, Any]:
    sensitivity = catalog.resource_sensitivity(inp.resource_id)
    permitted = catalog.is_permitted(inp.role, inp.resource_id, inp.action)
    risk = compute_risk(
        sensitivity=sensitivity, action=inp.action, device_trust=inp.device_trust,
        mfa_verified=inp.mfa_verified, failed_logins=inp.failed_logins,
        access_context=inp.access_context, rbac_permitted=permitted,
    )
    return {
        "role": inp.role, "action": inp.action, "resource_id": inp.resource_id,
        "resource_sensitivity": sensitivity,
        "sensitivity_level": catalog.SENSITIVITY_LEVEL.get(sensitivity, 4),
        "device_trust": inp.device_trust, "mfa_verified": inp.mfa_verified,
        "failed_logins": inp.failed_logins, "access_context": inp.access_context,
        "risk_score": risk.score, "rbac_permitted": permitted,
        "_risk": risk,
    }


def condition_matches(cond: Dict[str, Any], ctx: Dict[str, Any]) -> bool:
    """Evaluate one whitelisted condition. Raises KeyError/TypeError on malformed data."""
    fn = _COMPARATORS[cond["operator"]]
    return bool(fn(ctx[cond["field"]], cond["value"]))


def rule_matches(rule: PolicyRule, ctx: Dict[str, Any]) -> bool:
    return bool(rule.conditions) and all(condition_matches(c, ctx) for c in rule.conditions)


def _explain(decision: str, inp: AccessInput, ctx: Dict[str, Any], decisive: List[MatchedRule],
             rules_by_code: Dict[str, PolicyRule]) -> str:
    who = f"{inp.user_id} ({inp.role})"
    what = f"{inp.action} on '{inp.resource_id}' ({ctx['resource_sensitivity']} sensitivity)"
    risk = f"Risk score {ctx['risk_score']}/100 ({ctx['_risk'].level})."
    verb = {"ALLOW": "allowed", "DENY": "denied", "STEP_UP": "paused for step-up verification"}[decision]
    reasons = []
    for m in decisive[:3]:
        r = rules_by_code.get(m.code)
        text = r.description if r and r.description else m.name
        reasons.append(f"[{m.code}] {m.name}: {text}")
    if decisive and decisive[0].code == "SYS-DEFAULT-DENY":
        reasons = ["[SYS-DEFAULT-DENY] No ALLOW policy matched; the engine denies by default (fail-closed)."]
    return f"Request by {who} for {what} was {verb}. " + " ".join(reasons) + " " + risk


def evaluate(inp: AccessInput, rules: Iterable[PolicyRule]) -> EngineDecision:
    ctx = build_context(inp)
    risk = ctx["_risk"]
    matched: List[MatchedRule] = []
    skipped: List[str] = []
    rules_by_code: Dict[str, PolicyRule] = {}

    # System rule: backend RBAC enforcement (cannot be disabled).
    if not ctx["rbac_permitted"]:
        matched.append(MatchedRule("SYS-RBAC", "RBAC permission check", "DENY", 0, True, system=True))
        rules_by_code["SYS-RBAC"] = PolicyRule(
            "SYS-RBAC", "RBAC permission check",
            f"Role '{inp.role}' is not granted '{inp.action}' on '{inp.resource_id}' (least privilege).",
            [], "DENY", 0, True, True,
            "Request the permission through the resource owner's approval workflow instead of retrying.",
        )

    for rule in sorted(rules, key=lambda r: (r.priority, r.code)):
        if not (rule.enabled or rule.mandatory):
            continue
        try:
            hit = rule_matches(rule, ctx)
        except (KeyError, TypeError, ValueError):
            skipped.append(rule.code)  # malformed stored rule: ignored, never executed
            continue
        if hit:
            rules_by_code[rule.code] = rule
            matched.append(MatchedRule(rule.code, rule.name, rule.effect, rule.priority, rule.mandatory))

    effects = {m.effect for m in matched}
    if "DENY" in effects:
        decision = "DENY"
    elif "STEP_UP" in effects:
        decision = "STEP_UP"
    elif "ALLOW" in effects:
        decision = "ALLOW"
    else:
        decision = "DENY"
        matched.append(MatchedRule("SYS-DEFAULT-DENY", "Default deny", "DENY", 9999, True, system=True))

    matched.sort(key=lambda m: (-_SEVERITY[m.effect], m.priority, m.code))
    decisive = [m for m in matched if m.effect == decision]
    for m in decisive:
        m.decisive = True

    remediation: List[str] = []
    if decision == "ALLOW":
        remediation.append("No action required. Access is logged and continuously evaluated.")
    elif decisive and decisive[0].code == "SYS-DEFAULT-DENY":
        remediation.append("Lower the risk (trusted device, completed MFA, normal network) and retry, "
                           "or ask an administrator to add an explicit ALLOW policy.")
    else:
        for m in decisive:
            r = rules_by_code.get(m.code)
            if r and r.remediation and r.remediation not in remediation:
                remediation.append(r.remediation)
    if not remediation:
        remediation.append("Contact your security administrator.")

    explanation = _explain(decision, inp, ctx, decisive, rules_by_code)
    public_ctx = {k: v for k, v in ctx.items() if not k.startswith("_")}
    return EngineDecision(decision, risk.score, risk.level, risk.factors, matched,
                          explanation, remediation, public_ctx, skipped)
