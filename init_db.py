#!/usr/bin/env python3
"""Initialize the database and create an admin user.

Usage:
    python3 init_db.py [admin_password]

If no password is provided, one will be generated.
If FERNET_KEY is not set in .env, one will be generated and printed.
"""

import os
import sys
import secrets
import string

import bcrypt
from cryptography.fernet import Fernet

# Load .env before importing app
from dotenv import load_dotenv
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

from dyndns import create_app  # noqa: E402
from models import db, User  # noqa: E402


def generate_password(length=24):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def main():
    # Check/generate FERNET_KEY
    fernet_key = os.environ.get('FERNET_KEY')
    if not fernet_key:
        fernet_key = Fernet.generate_key().decode()
        print(f'Generated FERNET_KEY (add to .env):\nFERNET_KEY={fernet_key}\n')

    # Check/generate SECRET_KEY
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key or secret_key == 'change-me-in-production':
        secret_key = secrets.token_hex(32)
        print(f'Generated SECRET_KEY (add to .env):\nSECRET_KEY={secret_key}\n')

    app = create_app()

    with app.app_context():
        db.create_all()
        print('Database tables created.')

        # Create admin user if none exists
        admin = User.query.filter_by(role='admin').first()
        admin_totp_secret = os.environ.get('ADMIN_TOTP_SECRET')
        if admin:
            print(f'Admin user already exists: {admin.username}')
            if admin_totp_secret and not admin.has_totp:
                admin.set_totp_secret(admin_totp_secret)
                db.session.commit()
                print('Admin TOTP secret set from ADMIN_TOTP_SECRET env var.')
        else:
            password = sys.argv[1] if len(sys.argv) > 1 else generate_password()
            admin_password = os.environ.get('ADMIN_PASSWORD')

            if admin_password:
                # Use pre-hashed password from env
                hashed = admin_password
            else:
                hashed = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt()).decode()

            admin = User(username='admin', password_hash=hashed, role='admin', is_active=True)
            if admin_totp_secret:
                admin.set_totp_secret(admin_totp_secret)
            db.session.add(admin)
            db.session.commit()

            if not admin_password:
                print('Admin user created:')
                print('  Username: admin')
                print(f'  Password: {password}')
            else:
                print('Admin user created from ADMIN_PASSWORD env var.')
            if admin_totp_secret:
                print('Admin TOTP secret set from ADMIN_TOTP_SECRET env var.')


if __name__ == '__main__':
    main()
