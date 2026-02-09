#!/usr/bin/env python3
"""Migrate existing .env credentials into the database.

Reads USERNAME, PASSWORD, DOMAINS, AWS_*, NSUPDATE_* from .env
and creates corresponding database records.

Usage:
    python3 migrate_env.py
"""

import os

from dotenv import load_dotenv
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

from dyndns import create_app  # noqa: E402
from models import db, User, UserDomain, BackendConfig, encrypt_value  # noqa: E402


def main():
    app = create_app()

    with app.app_context():
        username = os.environ.get('USERNAME')
        password_hash = os.environ.get('PASSWORD')
        domains_str = os.environ.get('DOMAINS', '')

        if not username or not password_hash:
            print('No USERNAME/PASSWORD found in .env — nothing to migrate.')
            return

        # Create or find user
        user = User.query.filter_by(username=username).first()
        if user:
            print(f'User "{username}" already exists (id={user.id}).')
        else:
            user = User(username=username, password_hash=password_hash, role='user', is_active=True)
            db.session.add(user)
            db.session.flush()
            print(f'Created user "{username}" (id={user.id}).')

        # Create domain assignments
        has_aws = bool(os.environ.get('AWS_ACCESS_KEY_ID'))
        has_nsupdate = bool(os.environ.get('NSUPDATE_KEY'))

        if domains_str:
            for domain_name in domains_str.split(','):
                domain_name = domain_name.strip()
                if not domain_name:
                    continue

                if has_aws:
                    ud = UserDomain.query.filter_by(
                        user_id=user.id, domain_name=domain_name, backend_type='aws').first()
                    if not ud:
                        ud = UserDomain(user_id=user.id, domain_name=domain_name, backend_type='aws')
                        db.session.add(ud)
                        db.session.flush()
                        print(f'  Added domain "{domain_name}" (aws) for user "{username}".')
                    _set_aws_credentials(ud)

                if has_nsupdate:
                    ud = UserDomain.query.filter_by(
                        user_id=user.id, domain_name=domain_name, backend_type='nsupdate').first()
                    if not ud:
                        ud = UserDomain(user_id=user.id, domain_name=domain_name, backend_type='nsupdate')
                        db.session.add(ud)
                        db.session.flush()
                        print(f'  Added domain "{domain_name}" (nsupdate) for user "{username}".')
                    _set_nsupdate_credentials(ud)

        db.session.commit()
        print('Migration complete.')


def _set_aws_credentials(ud):
    aws_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if aws_key:
        _set_config(ud, 'aws_access_key_id', aws_key)
    if aws_secret:
        _set_config(ud, 'aws_secret_access_key', aws_secret)
    print(f'    Migrated AWS credentials for domain "{ud.domain_name}".')


def _set_nsupdate_credentials(ud):
    ns_key = os.environ.get('NSUPDATE_KEY')
    ns_algo = os.environ.get('NSUPDATE_ALGO')
    ns_secret = os.environ.get('NSUPDATE_SECRET')
    ns_server = os.environ.get('NSUPDATE_NAMESERVER')
    if ns_key:
        _set_config(ud, 'nsupdate_key', ns_key)
    if ns_algo:
        _set_config(ud, 'nsupdate_algo', ns_algo)
    if ns_secret:
        _set_config(ud, 'nsupdate_secret', ns_secret)
    if ns_server:
        _set_config(ud, 'nsupdate_nameserver', ns_server)
    print(f'    Migrated nsupdate credentials for domain "{ud.domain_name}".')


def _set_config(ud, key, value):
    existing = BackendConfig.query.filter_by(
        user_domain_id=ud.id, config_key=key).first()
    if existing:
        existing.config_value = encrypt_value(value)
    else:
        cfg = BackendConfig(user_domain_id=ud.id,
                            config_key=key, config_value=encrypt_value(value))
        db.session.add(cfg)


if __name__ == '__main__':
    main()
