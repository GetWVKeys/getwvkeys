from sqlalchemy import Column, ForeignKey, Integer, String, Table

from getwvkeys.models.Base import Base

user_device_association = Table(
    "user_device",
    Base.metadata,
    Column("user_id", String(255), ForeignKey("users.id"), nullable=False),
    Column("device_code", String(255), ForeignKey("devices.code")),
)
