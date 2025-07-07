"""empty message

Revision ID: 4dcee16042d2
Revises: 51d65f145c1f
Create Date: 2025-07-03 18:38:08.599989

"""

import base64
import hashlib
import logging
from typing import Sequence, Union

import sqlalchemy as sa
from pywidevine.device import Device, DeviceTypes
from sqlalchemy.dialects import mysql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4dcee16042d2"
down_revision: Union[str, None] = "51d65f145c1f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = "51d65f145c1f"

logger = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    # fix keys that have an invalid added_by by changing empty values to NULL
    logger.info("Fixing keys with invalid added_by values...")
    op.execute(
        "UPDATE keys_ SET added_by = NULL WHERE added_by IS NOT NULL AND added_by NOT IN (SELECT id FROM users);"
    )

    logger.info("Dropping foreign keys and altering columns...")
    op.drop_constraint("cdms_ibfk_1", "cdms", type_="foreignkey")
    op.drop_constraint("keys__ibfk_1", "keys_", type_="foreignkey")
    op.drop_constraint("prds_ibfk_1", "prds", type_="foreignkey")
    op.drop_constraint("user_prd_ibfk_2", "user_prd", type_="foreignkey")

    op.alter_column(
        "apikeys",
        "user_id",
        existing_type=mysql.VARCHAR(length=19),
        type_=sa.String(length=255),
        existing_nullable=False,
    )
    op.alter_column(
        "users",
        "id",
        existing_type=mysql.VARCHAR(length=19),
        type_=sa.String(length=255),
        existing_nullable=False,
    )

    op.alter_column(
        "cdms",
        "uploaded_by",
        existing_type=mysql.VARCHAR(length=19),
        type_=sa.String(length=255),
        existing_nullable=True,
    )

    op.create_foreign_key(
        "cdms_ibfk_1",
        "cdms",
        "users",
        ["uploaded_by"],
        ["id"],
        ondelete="SET NULL",  # or whatever was originally defined
    )

    op.create_foreign_key(
        "keys__ibfk_1",
        "keys_",
        "users",
        ["added_by"],
        ["id"],
        # No ON DELETE specified in original schema = RESTRICT default
    )

    op.create_foreign_key(
        "prds_ibfk_1",
        "prds",
        "users",
        ["uploaded_by"],
        ["id"],
        # No ON DELETE specified in original schema = RESTRICT default
    )

    op.create_foreign_key(
        "user_prd_ibfk_2", "user_prd", "users", ["user_id"], ["id"], ondelete="CASCADE"
    )

    logger.info("Creating new tables for WVDs...")

    op.create_table(
        "wvds",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column(
            "hash",
            sa.String(length=255, collation="utf8mb4_general_ci"),
            nullable=False,
        ),
        sa.Column("wvd", sa.Text(), nullable=False),
        sa.Column(
            "uploaded_by",
            sa.String(length=255, collation="utf8mb4_general_ci"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("hash"),
    )
    op.create_table(
        "user_wvd",
        sa.Column(
            "user_id",
            sa.String(length=255, collation="utf8mb4_general_ci"),
            nullable=False,
        ),
        sa.Column(
            "device_hash",
            sa.String(length=255, collation="utf8mb4_general_ci"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["device_hash"], ["wvds.hash"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    logger.info("Removing invalid CDMs")

    # DROP all cdms that have an empty private key or client id
    op.execute(
        "DELETE FROM cdms WHERE device_private_key = '' OR client_id_blob_filename = ''"
    )

    logger.info("Converting cdms to WVDs...")

    # run through all cdms and convert them to a WVD
    cdms = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT code,client_id_blob_filename,device_private_key,uploaded_by FROM cdms"
            )
        )
        .fetchall()
    )
    for code, client_id, private_key, uploaded_by in cdms:
        try:
            logger.info(f"Converting device {code} to WVD")
            wvd = Device(
                type_=DeviceTypes.ANDROID,
                security_level=3,
                flags=None,
                private_key=base64.b64decode(private_key),
                client_id=base64.b64decode(client_id),
            )

            wvd_raw = wvd.dumps()

            # calculate the hash of the wvd
            wvd_hash = hashlib.sha256(wvd_raw).hexdigest()

            wvd_b64 = base64.b64encode(wvd_raw).decode()

            # check if this wvd already exists
            existing_wvd = (
                op.get_bind()
                .execute(
                    sa.text("SELECT id FROM wvds WHERE hash = :hash"),
                    {"hash": wvd_hash},
                )
                .fetchone()
            )
            if not existing_wvd:
                # insert the new WVD
                op.get_bind().execute(
                    sa.text(
                        "INSERT INTO wvds (hash, wvd, uploaded_by) VALUES (:hash, :wvd, :uploaded_by)"
                    ),
                    {
                        "hash": wvd_hash,
                        "wvd": wvd_b64,
                        "uploaded_by": uploaded_by,
                    },
                )
                logger.info(f"Inserted new WVD for device {code} with hash {wvd_hash}")

                # add the WVD to the user
                op.get_bind().execute(
                    sa.text(
                        "INSERT INTO user_wvd (user_id, device_hash) VALUES (:user_id, :device_hash)"
                    ),
                    {
                        "user_id": uploaded_by,
                        "device_hash": wvd_hash,
                    },
                )
                logger.info(
                    f"Added WVD {wvd_hash} to user {uploaded_by} for device {code}"
                )
            else:
                # add it to the user
                op.get_bind().execute(
                    sa.text(
                        "INSERT INTO user_wvd (user_id, device_hash) VALUES (:user_id, :device_hash)"
                    ),
                    {
                        "user_id": uploaded_by,
                        "device_hash": wvd_hash,
                    },
                )
                logger.info(
                    f"Added existing WVD {wvd_hash} to user {uploaded_by} for device {code}"
                )

        except Exception as e:
            logger.error(
                f"Failed to convert device {code} to WVD: {e}\nPK: {private_key}\nCID: {client_id}"
            )
            # remove the device from the database
            op.get_bind().execute(
                sa.text("DELETE FROM cdms WHERE code = :code"), {"code": code}
            )

    op.drop_table("cdms")

    # ### end Alembic commands ###


def downgrade() -> None:
    raise NotImplementedError("Downgrade is not supported for this migration.")
