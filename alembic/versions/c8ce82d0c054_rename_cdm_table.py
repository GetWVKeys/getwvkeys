"""rename_cdm_table

Revision ID: c8ce82d0c054
Revises: f3df682d6393
Create Date: 2024-05-21 22:34:31.031258

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8ce82d0c054"
down_revision: Union[str, None] = "f3df682d6393"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = "f3df682d6393"


def upgrade() -> None:
    op.rename_table("cdms", "devices")


def downgrade() -> None:
    op.rename_table("devices", "cdms")
