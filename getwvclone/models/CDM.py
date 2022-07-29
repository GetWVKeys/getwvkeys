import time

from sqlalchemy import ForeignKey

from getwvclone.models.Shared import db


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
