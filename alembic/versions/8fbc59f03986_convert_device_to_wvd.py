"""convert_device_to_wvd

Revision ID: 8fbc59f03986
Revises: 684292138a0a
Create Date: 2024-07-24 16:35:56.530161

"""

import base64
import logging
from typing import Sequence, Union

import sqlalchemy as sa
from pywidevine.device import Device, DeviceTypes
from sqlalchemy.dialects import mysql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "8fbc59f03986"
down_revision: Union[str, None] = "684292138a0a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = "684292138a0a"

logger = logging.getLogger("alembic.runtime.migration")


def upgrade() -> None:
    # create the new wvd column and make it nullable temporarily
    op.add_column("devices", sa.Column("wvd", sa.Text(), nullable=True))

    # DROP all devices that have an empty private key or client id
    op.execute("DELETE FROM devices WHERE device_private_key = '' OR client_id_blob_filename = ''")

    # run through all devices and convert them to a WVD
    devices = (
        op.get_bind().execute(sa.text("SELECT code,client_id_blob_filename,device_private_key FROM devices")).fetchall()
    )
    for code, client_id, private_key in devices:
        logger.info(f"Converting device {code} to WVD")
        wvd = Device(
            type_=DeviceTypes.ANDROID,
            security_level=3,
            flags=None,
            private_key=base64.b64decode(private_key),
            client_id=base64.b64decode(client_id),
        )

        wvd_b64 = base64.b64encode(wvd.dumps()).decode()
        op.get_bind().execute(
            sa.text("UPDATE devices SET wvd = :wvd WHERE code = :code"), {"wvd": wvd_b64, "code": code}
        )

    # make the wvd column non-nullable
    op.alter_column("devices", "wvd", existing_type=sa.Text(), nullable=False)

    # remove the old columns
    op.drop_column("devices", "device_private_key")
    op.drop_column("devices", "client_id_blob_filename")


def downgrade() -> None:
    raise NotImplementedError("Downgrade is not supported for this migration.")
