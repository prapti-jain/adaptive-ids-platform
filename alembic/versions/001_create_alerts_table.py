"""create alerts table (SQLite + Postgres compatible)

Revision ID: 001_create_alerts
Revises:
Create Date: 2026-07-30 14:24:00.000000

"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001_create_alerts"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alerts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_name", sa.String(length=64), nullable=False),
        sa.Column("attack_type", sa.String(length=64), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("target_ip", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=32),
            server_default="OPEN",
            nullable=False,
        ),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_alerts_attack_type"), "alerts", ["attack_type"], unique=False)
    op.create_index(op.f("ix_alerts_source_ip"), "alerts", ["source_ip"], unique=False)
    op.create_index(op.f("ix_alerts_detected_at"), "alerts", ["detected_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_alerts_detected_at"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_source_ip"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_attack_type"), table_name="alerts")
    op.drop_table("alerts")
