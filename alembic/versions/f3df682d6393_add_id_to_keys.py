"""add_id_to_keys

Revision ID: f3df682d6393
Revises: e1238372d8d1
Create Date: 2024-03-08 18:45:36.917818

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3df682d6393"
down_revision: Union[str, None] = "e1238372d8d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = "e1238372d8d1"


def upgrade() -> None:
    # Rename old table
    op.execute("ALTER TABLE keys_ RENAME TO keys_old")

    # Create new table with correct data types
    op.create_table(
        "keys_",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True, unique=True),
        sa.Column("kid", sa.String(length=32), nullable=False),
        sa.Column("added_at", sa.Integer(), nullable=False),
        sa.Column("added_by", sa.String(length=19), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("license_url", sa.Text(), nullable=False),
        sa.Column("key_", sa.String(length=255), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # Copy data from the old table to the new table, setting added_by to NULL for invalid references, and strip the kid prefix
    op.execute(
        "INSERT INTO keys_ (kid, added_at, added_by, license_url, key_) "
        "SELECT kid, added_at, CASE WHEN added_by IN (SELECT id FROM users) THEN added_by ELSE NULL END, license_url, "
        "SUBSTRING_INDEX(SUBSTRING_INDEX(key_, ':', -2), ':', 1) FROM keys_old"
    )

    # Drop the old table
    op.drop_table("keys_old")


def downgrade() -> None:
    # throw an error if someone tries to downgrade
    raise NotImplementedError("Downgrade is not supported for this migration.")
