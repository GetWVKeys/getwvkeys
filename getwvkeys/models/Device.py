"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022-2024 Notaghost, Puyodead1 and GetWVKeys contributors 
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published
 by the Free Software Foundation, version 3 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import hashlib

from sqlalchemy import Column, ForeignKey, Integer, String, Text, event
from sqlalchemy.orm import relationship

from getwvkeys.models.Base import Base
from getwvkeys.models.UserDevice import user_device_association


def generate_code(client_id_blob_filename: str, device_private_key: str, uploaded_by: str) -> str:
    # get sha of client_id_blob_filename
    client_id_blob_filename_sha = hashlib.sha256(client_id_blob_filename.encode()).hexdigest()
    # get sha of device_private_key
    device_private_key_sha = hashlib.sha256(device_private_key.encode()).hexdigest()
    # get final hash
    return hashlib.sha256(f"{client_id_blob_filename_sha}:{device_private_key_sha}:{uploaded_by}".encode()).hexdigest()


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(Text, unique=True, nullable=False)
    client_id_blob_filename = Column(Text, nullable=False)
    device_private_key = Column(Text, nullable=False)
    uploaded_by = Column(String(255), ForeignKey("users.id"), nullable=False)
    info = Column(String(255), unique=True, nullable=False)
    users = relationship("User", secondary=user_device_association, back_populates="devices")

    def to_json(self):
        return {
            "id": self.id,
            "client_id_blob_filename": self.client_id_blob_filename,
            "device_private_key": self.device_private_key,
            "uploaded_by": self.uploaded_by,
            "code": self.code,
            "info": self.info,
        }


@event.listens_for(Device, "before_insert")
def set_info(mapper, connection, target):
    target.code = generate_code(target.client_id_blob_filename, target.device_private_key, target.uploaded_by)


@event.listens_for(Device, "before_update")
def update_info(mapper, connection, target):
    target.code = generate_code(target.client_id_blob_filename, target.device_private_key, target.uploaded_by)
