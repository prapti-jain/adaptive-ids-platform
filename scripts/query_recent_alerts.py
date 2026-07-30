#!/usr/bin/env python3
"""Print the 10 most recent rows from the alerts table.

Requires DATABASE_URL in .env. No psql client needed.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import select

from backend.database.models import AlertORM
from backend.database.session import SessionLocal


def main() -> int:
    db = SessionLocal()
    try:
        rows = db.scalars(
            select(AlertORM).order_by(AlertORM.detected_at.desc()).limit(10)
        ).all()
        if not rows:
            print("No rows in alerts table.")
            return 0

        print(
            f"{'ID':<38} {'ATTACK_TYPE':<18} {'SEVERITY':<10} "
            f"{'RISK':<8} DETECTED_AT"
        )
        print("-" * 100)
        for row in rows:
            print(
                f"{str(row.id):<38} {row.attack_type:<18} {row.severity:<10} "
                f"{row.risk_score:<8.4f} {row.detected_at}"
            )
        print(f"\nShowing {len(rows)} row(s).")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
