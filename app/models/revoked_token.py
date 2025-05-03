from app import db

class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, unique=True)  # JWT ID
    revoked_at = db.Column(db.DateTime, nullable=False)  # Timestamp when the token was revoked