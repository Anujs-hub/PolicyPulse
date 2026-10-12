"""Populate the audit log with deterministic demo evaluations so the dashboard has data.

Usage (from the project root):  python scripts/seed_demo_data.py [--count 60]
Uses the configured database (default: data/policypulse.db). Safe to run repeatedly.
"""
import argparse
import itertools
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.database import init_db, make_engine, make_session_factory  # noqa: E402
from app.services import audit_service, catalog, policy_service  # noqa: E402
from app.services.policy_engine import AccessInput, evaluate  # noqa: E402
from app.services.scenarios import SCENARIOS  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=60, help="extra random evaluations (default 60)")
    parser.add_argument("--seed", type=int, default=7, help="random seed for reproducibility")
    args = parser.parse_args()

    settings = get_settings()
    engine = make_engine(settings.database_url)
    factory = make_session_factory(engine)
    init_db(engine, factory)
    rng = random.Random(args.seed)
    users = {"admin": "alice", "analyst": "bob", "employee": "carol"}
    requests = [AccessInput(**s["request"]) for s in SCENARIOS]
    for _ in range(max(0, args.count)):
        role = rng.choice(list(users))
        resource = rng.choice(list(catalog.RESOURCES))
        perms = catalog.RESOURCES[resource]["permissions"][role]
        action = rng.choice(perms) if perms and rng.random() < 0.8 else rng.choice([a.value for a in catalog.Action])
        requests.append(AccessInput(
            users[role], role, resource, action,
            rng.choices(["trusted", "unmanaged", "untrusted"], [6, 3, 1])[0], rng.random() < 0.65,
            rng.choices([0, 1, 2, 3, 5, 7], [12, 3, 2, 2, 1, 1])[0],
            rng.choices(["normal", "unusual_time", "unusual_location", "anonymized_network"], [10, 2, 2, 1])[0],
        ))
    with factory() as db:
        rules = policy_service.load_rules(db)
        for inp in requests:
            audit_service.record_evaluation(db, inp, evaluate(inp, rules))
    print(f"Recorded {len(requests)} demo evaluations in {settings.database_url}")


if __name__ == "__main__":
    main()
