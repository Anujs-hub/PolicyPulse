# Policy Model

## Request attributes (all simulated)

| Attribute | Values |
|---|---|
| `user_id` | 1-64 chars of `A-Z a-z 0-9 _ . @ -` (a label, not verified) |
| `role` | `admin`, `analyst`, `employee` |
| `resource_id` | one of the catalog resources |
| `action` | `read`, `write`, `delete`, `admin` |
| `device_trust` | `trusted`, `unmanaged`, `untrusted` |
| `mfa_verified` | boolean (strict; strings/numbers are rejected) |
| `failed_logins` | integer 0-100 |
| `access_context` | `normal`, `unusual_time`, `unusual_location`, `anonymized_network` |

## Resources and RBAC (least privilege)

| Resource | Sensitivity | admin | analyst | employee |
|---|---|---|---|---|
| `public-wiki` | low | read, write, delete | read, write | read |
| `hr-portal` | medium | read, write | read | read |
| `siem-dashboard` | medium | read, write, delete | read, write | - |
| `customer-db` | high | read, write, delete | read | - |
| `finance-ledger` | high | read, write | - | - |
| `prod-admin-console` | critical | read, write, delete, admin | - | - |
| `secrets-vault` | critical | read, admin | - | - |

A request outside this matrix is denied by the hard-coded system rule `SYS-RBAC`. It is enforced in
`policy_engine.evaluate`, not in JavaScript.

## Policy structure

```json
{
  "name": "Require MFA for privileged actions",
  "description": "...",
  "conditions": [
    {"field": "mfa_verified", "operator": "eq", "value": false},
    {"field": "action", "operator": "in", "value": ["write", "delete", "admin"]}
  ],
  "effect": "STEP_UP",
  "priority": 100,
  "enabled": true,
  "remediation": "Complete multi-factor authentication, then resubmit the request."
}
```

All conditions are AND-ed. There is no free-form expression language and nothing is passed to `eval`/`exec`.

### Condition fields and operators

| Field | Type | Operators |
|---|---|---|
| `role`, `action`, `resource_id`, `resource_sensitivity`, `device_trust`, `access_context` | enum | `eq`, `neq`, `in`, `not_in` |
| `mfa_verified`, `rbac_permitted` | boolean | `eq`, `neq` |
| `failed_logins` (0-100), `risk_score` (0-100), `sensitivity_level` (1-4) | integer | `eq`, `neq`, `gt`, `gte`, `lt`, `lte` |

`risk_score` and `rbac_permitted` are computed by the engine before policies run.

### Validation rules (`policy_validation.py`)

- Unknown fields, operators, value types, out-of-range numbers or enum values are rejected (HTTP 422).
- 1-8 conditions per policy; `in`/`not_in` lists have 1-10 items.
- Name 3-80 chars (unique), description/remediation up to 500 chars, priority 1-1000.
- **ALLOW policies must contain `rbac_permitted eq true`**, so a custom policy can never grant what RBAC forbids.
- Policies created through the API are never `mandatory`.

## Precedence (explicit)

1. **System rules** - `SYS-RBAC` (priority 0) is always evaluated; `SYS-DEFAULT-DENY` (priority 9999) applies when nothing else matched.
2. **Eligibility** - enabled policies, plus *all* mandatory policies even if their `enabled` flag was altered in the database.
3. **Effect severity decides the outcome**: `DENY` > `STEP_UP` > `ALLOW`, independent of priority numbers.
4. **Priority** (lower number first) orders matched rules within the same effect; the first is the primary rule.
5. **Fail closed** - if no ALLOW, STEP_UP or DENY rule matched, the result is DENY.

Consequences: a mandatory DENY can never be overridden by an ALLOW (or a STEP_UP); an ALLOW at priority 1 still loses to a DENY at priority 999.

## Mandatory policies

`P-001` and `P-002` are flagged `mandatory`. Through the API they cannot be disabled, deleted, re-prioritised or have their
conditions/effect changed (HTTP 403); only `description` and `remediation` text may be edited. The engine also evaluates them
even if the database row is tampered with.

## Default policy set

| Code | Name | Effect | Priority | Mandatory |
|---|---|---|---|---|
| P-001 | Block excessive failed logins (>= 5) | DENY | 10 | yes |
| P-002 | Deny untrusted devices on high/critical resources | DENY | 20 | yes |
| P-003 | Deny anonymised networks for critical resources | DENY | 30 | no |
| P-004 | Deny risk score >= 85 | DENY | 40 | no |
| P-101 | Require MFA for write/delete/admin | STEP_UP | 100 | no |
| P-102 | Require MFA for high/critical resources | STEP_UP | 110 | no |
| P-103 | Step up on unusual context (no MFA) | STEP_UP | 120 | no |
| P-104 | Step up after >= 3 failed logins (no MFA) | STEP_UP | 130 | no |
| P-105 | Step up when risk >= 60 (no MFA) | STEP_UP | 140 | no |
| P-201 | Allow RBAC-permitted requests with risk <= 49 | ALLOW | 500 | no |
| P-202 | Allow RBAC-permitted requests with MFA on a trusted device, risk <= 69 | ALLOW | 510 | no |

Step-up policies require `mfa_verified = false`; once MFA is (claimed) verified they stop matching, so the simulation does not loop.
A request with MFA verified but a risk score of 70-84 matches no ALLOW policy and is denied by default.

## Explanations and remediation

The explanation names the user, role, action, resource, outcome, up to three decisive rules with their descriptions, and the risk score.
Remediation text comes from the decisive rules' `remediation` field (de-duplicated); `SYS-RBAC` and `SYS-DEFAULT-DENY` provide their own advice.
