"""add_id_to_keys

Revision ID: 8866b90c97bf
Revises: a82c1bce8c6d
Create Date: 2023-10-01 22:40:53.681034

"""
import time
from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "8866b90c97bf"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # rename keys temporary table
    op.execute("ALTER TABLE keys_ RENAME TO keys_old")

    # create new keys table
    op.create_table(
        "keys_",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("kid", sa.String(length=32), nullable=False),
        sa.Column("added_at", sa.Integer(), nullable=False, default=int(time.time())),
        sa.Column(
            "added_by", sa.String(length=255), sa.ForeignKey("users.id"), nullable=True
        ),
        sa.Column("license_url", sa.Text(), nullable=False),
        sa.Column("key_", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["added_by"], ["users.id"]),
    )

    # Copy data from the old table to the new table, setting added_by to NULL for invalid references
    conn = op.get_bind()
    conn.execute(
        """
        INSERT INTO keys_ (kid, added_at, added_by, license_url, key_)
        SELECT kid, added_at, CASE WHEN added_by IN (SELECT id FROM users) THEN added_by ELSE NULL END, license_url, key_
        FROM keys_old
    """
    )

    # Drop the old table
    op.drop_table("keys_old")


def downgrade() -> None:
    # throw an error if someone tries to downgrade
    raise NotImplementedError("Downgrade is not supported for this migration.")
