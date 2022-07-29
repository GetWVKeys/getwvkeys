from getwvclone.models.Shared import db


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(255), primary_key=True, nullable=False, unique=True)
    username = db.Column(db.String(255), nullable=False)
    discriminator = db.Column(db.String(255), nullable=False)
    avatar = db.Column(db.String(255), nullable=True)
    public_flags = db.Column(db.Integer, nullable=False)
    api_key = db.Column(db.String(255), nullable=False)
    flags = db.Column(db.Integer, default=0, nullable=False)
