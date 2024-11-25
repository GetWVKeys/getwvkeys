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

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from getwvkeys.models.Base import Base
from getwvkeys.models.UserDevice import user_device_association


def generate_device_code(client_id_blob_filename: str, device_private_key: str) -> str:
    # get sha of client_id_blob_filename
    client_id_blob_filename_sha = hashlib.sha256(client_id_blob_filename.encode()).hexdigest()
    # get sha of device_private_key
    device_private_key_sha = hashlib.sha256(device_private_key.encode()).hexdigest()
    # get final hash
    return hashlib.sha256(f"{client_id_blob_filename_sha}:{device_private_key_sha}".encode()).hexdigest()


class Device(Base):
    __tablename__ = "devices"
    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String(255), unique=True, nullable=False)
    wvd = Column(Text, nullable=False)
    uploaded_by = Column(String(255), ForeignKey("users.id"), nullable=False)
    info = Column(String(255), nullable=False)
    users = relationship("User", secondary=user_device_association, back_populates="devices")

    def to_json(self):
        return {
            "id": self.id,
            "wvd": self.wvd,
            "uploaded_by": self.uploaded_by,
            "code": self.code,
            "info": self.info,
        }
