"""Create the database tables and seed the default policies.

Usage (from the project root):  python scripts/init_db.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.database import init_db, make_engine, make_session_factory  # noqa: E402


def main() -> None:
    settings = get_settings()
    engine = make_engine(settings.database_url)
    init_db(engine, make_session_factory(engine))
    print(f"Database ready: {settings.database_url}")


if __name__ == "__main__":
    main()
