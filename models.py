from datetime import datetime, timezone
from cryptography.fernet import Fernet
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()


def _get_fernet():
    key = current_app.config.get('FERNET_KEY')
    if not key:
        raise RuntimeError('FERNET_KEY not configured — cannot encrypt/decrypt secrets')
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_value(plaintext):
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(ciphertext):
    return _get_fernet().decrypt(ciphertext.encode()).decode()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))

    totp_secret = db.Column(db.Text, nullable=True)

    hostnames = db.relationship('Hostname', back_populates='user', cascade='all, delete-orphan')

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def has_totp(self):
        return self.totp_secret is not None

    def get_totp_secret(self):
        if self.totp_secret is None:
            return None
        return decrypt_value(self.totp_secret)

    def set_totp_secret(self, secret):
        if secret is None:
            self.totp_secret = None
        else:
            self.totp_secret = encrypt_value(secret)


class Domain(db.Model):
    __tablename__ = 'domains'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    backends = db.relationship('DomainBackend', back_populates='domain', cascade='all, delete-orphan')
    hostnames = db.relationship('Hostname', back_populates='domain', cascade='all, delete-orphan')


class DomainBackend(db.Model):
    __tablename__ = 'domain_backends'

    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id', ondelete='CASCADE'), nullable=False)
    backend_type = db.Column(db.String(20), nullable=False)

    domain = db.relationship('Domain', back_populates='backends')
    configs = db.relationship('BackendConfig', back_populates='domain_backend', cascade='all, delete-orphan')

    __table_args__ = (db.UniqueConstraint('domain_id', 'backend_type'),)

    def get_credentials(self):
        creds = {}
        for cfg in self.configs:
            creds[cfg.config_key] = decrypt_value(cfg.config_value)
        return creds

    @property
    def has_credentials(self):
        return len(self.configs) > 0


class Hostname(db.Model):
    __tablename__ = 'hostnames'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), unique=True, nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('domains.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    domain = db.relationship('Domain', back_populates='hostnames')
    user = db.relationship('User', back_populates='hostnames')


class BackendConfig(db.Model):
    __tablename__ = 'backend_configs'

    id = db.Column(db.Integer, primary_key=True)
    domain_backend_id = db.Column(db.Integer, db.ForeignKey('domain_backends.id', ondelete='CASCADE'), nullable=False)
    config_key = db.Column(db.String(80), nullable=False)
    config_value = db.Column(db.Text, nullable=False)

    domain_backend = db.relationship('DomainBackend', back_populates='configs')

    __table_args__ = (db.UniqueConstraint('domain_backend_id', 'config_key'),)


class Event(db.Model):
    __bind_key__ = 'events'
    __tablename__ = 'events'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(80), nullable=False)
    event_type = db.Column(db.String(30), nullable=False)
    hostname = db.Column(db.String(255))
    ip_address = db.Column(db.String(45))
    backend_type = db.Column(db.String(20))
    response = db.Column(db.String(20))
    detail = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)
