"""Static catalog of roles, actions, resources and the RBAC permission matrix.

Everything here is *demonstration data*. The RBAC matrix is enforced on the
backend by the policy engine (system rule ``SYS-RBAC``), never by the frontend.
"""
from enum import Enum
from typing import Dict, List, Optional


class Role(str, Enum):
    admin = "admin"
    analyst = "analyst"
    employee = "employee"


class Action(str, Enum):
    read = "read"
    write = "write"
    delete = "delete"
    admin = "admin"


class Sensitivity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class DeviceTrust(str, Enum):
    trusted = "trusted"
    unmanaged = "unmanaged"
    untrusted = "untrusted"


class AccessContext(str, Enum):
    normal = "normal"
    unusual_time = "unusual_time"
    unusual_location = "unusual_location"
    anonymized_network = "anonymized_network"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"


SENSITIVITY_LEVEL: Dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# resource_id -> definition. `permissions` is the least-privilege RBAC matrix.
RESOURCES: Dict[str, dict] = {
    "public-wiki": {
        "name": "Public Wiki", "sensitivity": "low",
        "description": "Company-wide knowledge base.",
        "permissions": {"admin": ["read", "write", "delete"], "analyst": ["read", "write"], "employee": ["read"]},
    },
    "hr-portal": {
        "name": "HR Portal", "sensitivity": "medium",
        "description": "Leave requests and personal HR records.",
        "permissions": {"admin": ["read", "write"], "analyst": ["read"], "employee": ["read"]},
    },
    "siem-dashboard": {
        "name": "SIEM Dashboard", "sensitivity": "medium",
        "description": "Security event monitoring console.",
        "permissions": {"admin": ["read", "write", "delete"], "analyst": ["read", "write"], "employee": []},
    },
    "customer-db": {
        "name": "Customer Database", "sensitivity": "high",
        "description": "Customer PII and account records.",
        "permissions": {"admin": ["read", "write", "delete"], "analyst": ["read"], "employee": []},
    },
    "finance-ledger": {
        "name": "Finance Ledger", "sensitivity": "high",
        "description": "General ledger and payment approvals.",
        "permissions": {"admin": ["read", "write"], "analyst": [], "employee": []},
    },
    "prod-admin-console": {
        "name": "Production Admin Console", "sensitivity": "critical",
        "description": "Infrastructure administration for production systems.",
        "permissions": {"admin": ["read", "write", "delete", "admin"], "analyst": [], "employee": []},
    },
    "secrets-vault": {
        "name": "Secrets Vault", "sensitivity": "critical",
        "description": "Credential and key storage (simulated).",
        "permissions": {"admin": ["read", "admin"], "analyst": [], "employee": []},
    },
}

SAMPLE_IDENTITIES: List[dict] = [
    {"user_id": "alice", "role": "admin", "label": "alice (admin)"},
    {"user_id": "bob", "role": "analyst", "label": "bob (analyst)"},
    {"user_id": "carol", "role": "employee", "label": "carol (employee)"},
]


def get_resource(resource_id: str) -> Optional[dict]:
    return RESOURCES.get(resource_id)


def resource_sensitivity(resource_id: str) -> str:
    """Unknown resources are treated as critical (fail closed)."""
    res = RESOURCES.get(resource_id)
    return res["sensitivity"] if res else "critical"


def is_permitted(role: str, resource_id: str, action: str) -> bool:
    res = RESOURCES.get(resource_id)
    if not res:
        return False
    return action in res["permissions"].get(role, [])
