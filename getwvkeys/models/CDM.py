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

from sqlalchemy import ForeignKey

from getwvkeys.models.Shared import db


class CDM(db.Model):
    __tablename__ = "cdms"
    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    session_id_type = db.Column(db.String(255), nullable=False, default="android")
    security_level = db.Column(db.Integer, nullable=False, default=3)
    client_id_blob_filename = db.Column(db.Text, nullable=False)
    device_private_key = db.Column(db.Text, nullable=False)
    code = db.Column(db.Text, nullable=False)
    uploaded_by = db.Column(db.String(255), ForeignKey("users.id"), nullable=True)

    def to_json(self):
        return {
            "id": self.id,
            "session_id_type": self.session_id_type,
            "security_level": self.security_level,
            "client_id_blob_filename": self.client_id_blob_filename,
            "device_private_key": self.device_private_key,
            "code": self.code,
            "uploaded_by": self.uploaded_by,
        }
