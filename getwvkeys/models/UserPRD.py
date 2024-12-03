from sqlalchemy import Column, ForeignKey, String, Table

from getwvkeys.models.Base import Base

user_prd_association = Table(
    "user_prd",
    Base.metadata,
    Column("user_id", String(255), ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
    Column("device_hash", String(255), ForeignKey("prds.hash", ondelete="CASCADE"), nullable=False),
)
