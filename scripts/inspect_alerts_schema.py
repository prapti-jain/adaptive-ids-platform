#!/usr/bin/env python3
"""Print the live ``alerts`` table schema via SQLAlchemy inspect().

Requires DATABASE_URL in .env (cloud or local). No psql client needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine, inspect

from backend.config.settings import settings


def main() -> int:
    engine = create_engine(settings.DATABASE_URL)
    inspector = inspect(engine)

    if "alerts" not in inspector.get_table_names():
        print("Table 'alerts' not found. Run: alembic upgrade head")
        return 1

    print("Table: alerts")
    print(f"{'COLUMN':<20} {'TYPE':<30} {'NULLABLE':<10} {'DEFAULT'}")
    print("-" * 80)
    for col in inspector.get_columns("alerts"):
        default = col.get("default")
        print(
            f"{col['name']:<20} {str(col['type']):<30} "
            f"{str(col['nullable']):<10} {default}"
        )

    indexes = inspector.get_indexes("alerts")
    if indexes:
        print("\nIndexes:")
        for idx in indexes:
            print(f"  {idx['name']}: columns={idx['column_names']} unique={idx['unique']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
