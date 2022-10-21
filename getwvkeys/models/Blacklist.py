"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022 Notaghost, Puyodead1 and GetWVKeys contributors 
 
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from getwvkeys.models.Shared import db


class CDM(db.Model):
    __tablename__ = "blacklist"
    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    url = db.Column(db.String(255), nullable=False)
    partial = db.Column(db.Boolean, nullable=False, default=0)

    def to_json(self):
        return {
            "id": self.id,
            "url": self.url,
            "partial": self.partial,
        }
