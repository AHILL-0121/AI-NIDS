"""alert notified severity

Revision ID: 5b2d0c9e71a4
Revises: 1885195ec165
Create Date: 2026-09-23 10:12:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "5b2d0c9e71a4"
down_revision: str | None = "1885195ec165"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.add_column(sa.Column("notified_severity", sa.String(length=16), nullable=True))
    # Alerts that existed before notifications were added count as already announced.
    op.execute("UPDATE alerts SET notified_severity = severity")


def downgrade() -> None:
    with op.batch_alter_table("alerts", schema=None) as batch_op:
        batch_op.drop_column("notified_severity")
