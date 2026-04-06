from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin  # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from typing import Dict

db = SQLAlchemy()


class User(UserMixin, db.Model):  # type: ignore[name-defined]
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_id(self) -> str:
        return str(self.id)


# For backward compatibility, but we'll use the database
users: Dict[str, str] = {}  # Remove this later
