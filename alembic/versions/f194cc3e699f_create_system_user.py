"""create system user

Revision ID: f194cc3e699f
Revises: 8fbc59f03986
Create Date: 2024-08-01 12:41:28.108426

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f194cc3e699f"
down_revision: Union[str, None] = "8fbc59f03986"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        INSERT INTO `users` (`id`, `username`, `discriminator`, `avatar`, `public_flags`, `api_key`, `flags`) VALUES ('0000000000000000000', 'System', '0', NULL, '0', '0', '64');
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DELETE FROM `users` WHERE `id` = '0000000000000000000';
        """
    )
