"""create ip_reputation table (SQLite + Postgres compatible)

Revision ID: 002_create_ip_reputation
Revises: 001_create_alerts
Create Date: 2026-07-30 14:56:00.000000

"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002_create_ip_reputation"
down_revision: Union[str, Sequence[str], None] = "001_create_alerts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ip_reputation",
        sa.Column("ip", sa.String(length=64), nullable=False),
        sa.Column("reputation_score", sa.Float(), nullable=False),
        sa.Column(
            "is_known_malicious",
            sa.Boolean(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("geo_country", sa.String(length=8), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.PrimaryKeyConstraint("ip"),
    )


def downgrade() -> None:
    op.drop_table("ip_reputation")
