"""update_device_model

Revision ID: af5d6ca3a942
Revises: c8ce82d0c054
Create Date: 2024-05-22 18:37:39.203649

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "af5d6ca3a942"
down_revision: Union[str, None] = "c8ce82d0c054"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = "c8ce82d0c054"


def upgrade() -> None:
    op.alter_column("devices", "code", new_column_name="info", existing_type=sa.String(255))  # rename code to info
    op.add_column(
        "devices",
        sa.Column(
            "code",
            sa.String(length=255),
            nullable=True,
            default=sa.text(
                "sha2(concat(convert(sha2(convert(`client_id_blob_filename` using utf8mb4),256) using utf8mb4),':',convert(sha2(convert(`client_id_blob_filename` using utf8mb4),256) using utf8mb4),':',convert(`uploaded_by` using utf8mb4)),256)"
            ),
        ),
    )  # add new code column

    # remove all rows where updated_by is null
    op.execute("DELETE FROM devices WHERE uploaded_by IS NULL")

    # set uploaded_by to non nullable
    op.alter_column("devices", "uploaded_by", nullable=False, existing_type=sa.String(255))

    # generate code for rows as a sha256 in the format of "client_id_blob_filename sha256:device_private_key sha265:uploaded_by"
    op.execute(
        """
        UPDATE devices 
        SET code = SHA2(
            CONCAT(
                SHA2(CONVERT(client_id_blob_filename USING utf8mb4), 256), 
                ':', 
                SHA2(CONVERT(client_id_blob_filename USING utf8mb4), 256), 
                ':', 
                CONVERT(uploaded_by USING utf8mb4)
            ), 
            256
        )
        """
    )

    # remove any rows that are duplicates of code, keeping one. this will fix issues with the unique constraint added next
    op.execute(
        """
        DELETE FROM devices 
        WHERE id NOT IN (
            SELECT id 
            FROM (
                SELECT id 
                FROM devices 
                GROUP BY code 
                HAVING COUNT(*) > 1
            ) 
            AS t
        )
        """
    )

    op.create_unique_constraint(None, "devices", ["code"])  # create the unique constraint on code

    # remove useless columns
    op.drop_column("devices", "security_level")
    op.drop_column("devices", "session_id_type")


def downgrade() -> None:
    raise NotImplementedError("Downgrade is not supported for this migration.")
