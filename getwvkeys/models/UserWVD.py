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

from sqlalchemy import Column, ForeignKey, String, Table

from getwvkeys.models.Base import Base

user_wvd_association = Table(
    "user_wvd",
    Base.metadata,
    Column(
        "user_id",
        String(255, collation="utf8mb4_general_ci"),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "device_hash",
        String(255, collation="utf8mb4_general_ci"),
        ForeignKey("wvds.hash", ondelete="CASCADE"),
        nullable=False,
    ),
)
