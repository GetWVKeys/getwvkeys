import time

from sqlalchemy import ForeignKey

from getwvclone.models.Shared import db


class Key(db.Model):
    __tablename__ = "keys_"
    id = db.Column(db.Integer, primary_key=True, nullable=False, autoincrement=True)
    kid = db.Column(db.String(32), nullable=False)
    added_at = db.Column(db.Integer, nullable=False, default=int(time.time()))
    added_by = db.Column(db.String(18), ForeignKey("users.id"), nullable=True)
    license_url = db.Column(db.Text, nullable=False)
    key_ = db.Column(db.String(255), nullable=False)
