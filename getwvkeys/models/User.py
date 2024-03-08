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

from getwvkeys.models.Shared import db


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(255), primary_key=True, nullable=False, unique=True)
    username = db.Column(db.String(255), nullable=False)
    discriminator = db.Column(db.String(255), nullable=False)
    avatar = db.Column(db.String(255), nullable=True)
    public_flags = db.Column(db.Integer, nullable=False)
    api_key = db.Column(db.String(255), nullable=False)
    flags = db.Column(db.Integer, default=0, nullable=False)
