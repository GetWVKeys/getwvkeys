from getwvclone.models.Shared import db


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
