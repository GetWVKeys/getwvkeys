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

import time

from sqlalchemy import Column, Integer, String
from sqlalchemy.sql import func

from getwvkeys.models.Base import Base


class KeyCount(Base):
    __tablename__ = "key_count_cache"

    id = Column(Integer, primary_key=True, nullable=False, unique=True, autoincrement=True)
    count_value = Column(Integer, nullable=False, default=0)
    last_updated = Column(Integer, nullable=False, default=lambda: int(time.time()))

    def to_json(self):
        return {
            "id": self.id,
            "count_value": self.count_value,
            "last_updated": self.last_updated,
        }
