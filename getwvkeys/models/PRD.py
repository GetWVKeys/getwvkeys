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

from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from getwvkeys.models.Base import Base
from getwvkeys.models.UserPRD import user_prd_association


class PRD(Base):
    __tablename__ = "prds"
    id = Column(Integer, primary_key=True, autoincrement=True)
    hash = Column(
        String(255, collation="utf8mb4_general_ci"), unique=True, nullable=False
    )
    prd = Column(Text, nullable=False)
    uploaded_by = Column(
        String(255, collation="utf8mb4_general_ci"),
        ForeignKey("users.id"),
        nullable=False,
    )
    users = relationship("User", secondary=user_prd_association, back_populates="prds")

    def to_json(self):
        return {
            "id": self.id,
            "prd": self.prd,
            "uploaded_by": self.uploaded_by,
            "hash": self.hash,
        }
