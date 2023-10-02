"""
 This file is part of the GetWVKeys project (https://github.com/GetWVKeys/getwvkeys)
 Copyright (C) 2022-2023 Notaghost, Puyodead1 and GetWVKeys contributors 
 
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

from sqlalchemy import Column, Integer, String

from getwvkeys.models.Base import Base


class User(Base):
    __tablename__ = "users"
    id = Column(String(255), primary_key=True, nullable=False, unique=True)
    username = Column(String(255), nullable=False)
    discriminator = Column(String(255), nullable=False)
    avatar = Column(String(255), nullable=True)
    public_flags = Column(Integer, nullable=False)
    api_key = Column(String(255), nullable=False)
    flags = Column(Integer, default=0, nullable=False)
