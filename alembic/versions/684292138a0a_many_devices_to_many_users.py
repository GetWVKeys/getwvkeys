"""many devices to many users

Revision ID: 684292138a0a
Revises: c8ce82d0c054
Create Date: 2024-07-23 19:26:35.940451

"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "684292138a0a"
down_revision: Union[str, None] = "c8ce82d0c054"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = "c8ce82d0c054"


def upgrade() -> None:
    # Remove columns from devices table that are no longer needed
    op.drop_column("devices", "security_level")
    op.drop_column("devices", "session_id_type")

    # rename code to info
    op.alter_column("devices", "code", new_column_name="info", existing_type=sa.String(255))
    op.add_column(
        "devices",
        sa.Column(
            "code",
            sa.String(length=255),
            nullable=False,
            default=sa.text(
                """
                SHA2(
                    CONCAT(
                        SHA2(CONVERT(client_id_blob_filename USING utf8mb4), 256),
                        ':',
                        SHA2(CONVERT(client_id_blob_filename USING utf8mb4), 256)
                    ),
                    256
                )
                """
            ),
        ),
    )

    # remove all rows where uploaded_by is null, as they are not associated with a user
    op.execute("DELETE FROM devices WHERE uploaded_by IS NULL")
    op.alter_column("devices", "uploaded_by", nullable=False, existing_type=sa.String(255))

    # generate code for rows as a sha256 in the format of "client_id_blob_filename sha256:device_private_key sha265:uploaded_by"
    op.execute(
        """
        UPDATE devices
        SET code = SHA2(
            CONCAT(
                SHA2(CONVERT(client_id_blob_filename USING utf8mb4), 256),
                ':',
                SHA2(CONVERT(client_id_blob_filename USING utf8mb4), 256)
            ),
            256
        )
        """
    )

    # for mapping, cause we need to dedupe and create a unique constraint
    op.execute("DELETE FROM devices WHERE id NOT IN (SELECT MIN(id) FROM devices GROUP BY code)")
    op.create_unique_constraint(None, "devices", ["code"])

    # create a user <-> device association table
    op.create_table(
        "user_device",
        sa.Column("user_id", sa.VARCHAR(255), nullable=False),
        sa.Column("device_code", sa.VARCHAR(255), nullable=False),
        sa.ForeignKeyConstraint(["device_code"], ["devices.code"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )

    # Insert existing data into user_device table
    old_devices = op.get_bind().execute(sa.text("SELECT * FROM devices")).fetchall()
    user_device_insert = [f"('{device[4]}', '{device[5]}')" for device in old_devices]
    if user_device_insert:
        user_device_insert_sql = "INSERT INTO user_device (user_id, device_code) VALUES " + ",".join(user_device_insert)
        op.execute(sa.text(user_device_insert_sql))
    else:
        print("No devices found to insert into user_device table.")


def downgrade() -> None:
    raise NotImplementedError("Downgrade is not supported for this migration.")
