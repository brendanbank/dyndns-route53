#!/usr/bin/env python3
"""Migrate existing .env credentials into the database.

Reads USERNAME, PASSWORD, DOMAINS, AWS_*, NSUPDATE_* from .env
and creates corresponding database records using the new domain model.

Usage:
    python3 migrate_env.py
"""

import os

from dotenv import load_dotenv
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

from dyndns import create_app  # noqa: E402
from models import db, User, Domain, DomainBackend, BackendConfig, encrypt_value  # noqa: E402


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

        # Detect available backends
        has_aws = bool(os.environ.get('AWS_ACCESS_KEY_ID'))
        has_nsupdate = bool(os.environ.get('NSUPDATE_KEY'))

        if domains_str:
            for domain_name in domains_str.split(','):
                domain_name = domain_name.strip()
                if not domain_name:
                    continue

                # Create or find Domain
                domain = Domain.query.filter_by(name=domain_name).first()
                if not domain:
                    domain = Domain(name=domain_name)
                    db.session.add(domain)
                    db.session.flush()
                    print(f'  Created domain "{domain_name}".')
                else:
                    print(f'  Domain "{domain_name}" already exists.')

                if has_aws:
                    db_backend = DomainBackend.query.filter_by(
                        domain_id=domain.id, backend_type='aws').first()
                    if not db_backend:
                        db_backend = DomainBackend(domain_id=domain.id, backend_type='aws')
                        db.session.add(db_backend)
                        db.session.flush()
                        print(f'    Added aws backend for "{domain_name}".')
                    _set_aws_credentials(db_backend)

                if has_nsupdate:
                    db_backend = DomainBackend.query.filter_by(
                        domain_id=domain.id, backend_type='nsupdate').first()
                    if not db_backend:
                        db_backend = DomainBackend(domain_id=domain.id, backend_type='nsupdate')
                        db.session.add(db_backend)
                        db.session.flush()
                        print(f'    Added nsupdate backend for "{domain_name}".')
                    _set_nsupdate_credentials(db_backend)

        db.session.commit()
        print('Migration complete.')


def _set_aws_credentials(db_backend):
    aws_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')
    if aws_key:
        _set_config(db_backend, 'aws_access_key_id', aws_key)
    if aws_secret:
        _set_config(db_backend, 'aws_secret_access_key', aws_secret)
    print(f'    Migrated AWS credentials for backend id={db_backend.id}.')


def _set_nsupdate_credentials(db_backend):
    ns_key = os.environ.get('NSUPDATE_KEY')
    ns_algo = os.environ.get('NSUPDATE_ALGO')
    ns_secret = os.environ.get('NSUPDATE_SECRET')
    ns_server = os.environ.get('NSUPDATE_NAMESERVER')
    if ns_key:
        _set_config(db_backend, 'nsupdate_key', ns_key)
    if ns_algo:
        _set_config(db_backend, 'nsupdate_algo', ns_algo)
    if ns_secret:
        _set_config(db_backend, 'nsupdate_secret', ns_secret)
    if ns_server:
        _set_config(db_backend, 'nsupdate_nameserver', ns_server)
    print(f'    Migrated nsupdate credentials for backend id={db_backend.id}.')


def _set_config(db_backend, key, value):
    existing = BackendConfig.query.filter_by(
        domain_backend_id=db_backend.id, config_key=key).first()
    if existing:
        existing.config_value = encrypt_value(value)
    else:
        cfg = BackendConfig(domain_backend_id=db_backend.id,
                            config_key=key, config_value=encrypt_value(value))
        db.session.add(cfg)


if __name__ == '__main__':
    main()
