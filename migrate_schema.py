#!/usr/bin/env python3
"""Migrate old schema (UserDomain/BackendConfig) to new schema
(Domain/DomainBackend/Hostname/BackendConfig).

Run once after deploying the new code against an existing database.

Usage:
    python3 migrate_schema.py
"""

import os

from dotenv import load_dotenv
basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

from dyndns import create_app  # noqa: E402
from models import db, Domain, DomainBackend, BackendConfig, Hostname  # noqa: E402


def main():
    app = create_app()

    with app.app_context():
        # Check if old tables exist
        inspector = db.inspect(db.engine)
        if 'user_domains' not in inspector.get_table_names():
            print('Old user_domains table not found — nothing to migrate.')
            return

        # Read old data
        old_uds = db.session.execute(db.text(
            'SELECT id, user_id, domain_name, backend_type FROM user_domains'
        )).fetchall()

        if not old_uds:
            print('No records in user_domains — nothing to migrate.')
            return

        old_configs = db.session.execute(db.text(
            'SELECT user_domain_id, config_key, config_value FROM backend_configs'
        )).fetchall()

        # Build lookup: old_ud_id -> list of (key, value)
        config_map = {}
        for ud_id, key, val in old_configs:
            config_map.setdefault(ud_id, []).append((key, val))

        # Step 1: Collect unique domain names -> create Domain records
        domain_names = set()
        for _, _, domain_name, _ in old_uds:
            domain_names.add(domain_name.lower())

        domain_objs = {}
        for name in sorted(domain_names):
            d = Domain.query.filter_by(name=name).first()
            if not d:
                d = Domain(name=name)
                db.session.add(d)
                db.session.flush()
                print(f'Created domain: {name}')
            else:
                print(f'Domain already exists: {name}')
            domain_objs[name] = d

        # Step 2: Collect unique (domain_name, backend_type) -> create DomainBackend records
        backend_pairs = set()
        for _, _, domain_name, backend_type in old_uds:
            backend_pairs.add((domain_name.lower(), backend_type))

        db_backend_objs = {}
        for domain_name, backend_type in sorted(backend_pairs):
            domain = domain_objs[domain_name]
            db_b = DomainBackend.query.filter_by(domain_id=domain.id, backend_type=backend_type).first()
            if not db_b:
                db_b = DomainBackend(domain_id=domain.id, backend_type=backend_type)
                db.session.add(db_b)
                db.session.flush()
                print(f'  Created backend: {backend_type} for {domain_name}')
            else:
                print(f'  Backend already exists: {backend_type} for {domain_name}')
            db_backend_objs[(domain_name, backend_type)] = db_b

        # Step 3: Migrate credentials (pick first user's creds per backend)
        migrated_backends = set()
        for ud_id, user_id, domain_name, backend_type in old_uds:
            key = (domain_name.lower(), backend_type)
            db_b = db_backend_objs[key]

            if key in migrated_backends:
                # Already migrated creds from another user
                if ud_id in config_map:
                    print(f'  WARNING: Skipping credentials from user_domain {ud_id} '
                          f'(user_id={user_id}) for {domain_name}/{backend_type} — '
                          f'already migrated from another user')
                continue

            configs = config_map.get(ud_id, [])
            if configs:
                for config_key, config_value in configs:
                    existing = BackendConfig.query.filter_by(
                        domain_backend_id=db_b.id, config_key=config_key).first()
                    if not existing:
                        cfg = BackendConfig(
                            domain_backend_id=db_b.id,
                            config_key=config_key,
                            config_value=config_value,  # already encrypted
                        )
                        db.session.add(cfg)
                print(f'    Migrated {len(configs)} credential(s) for {domain_name}/{backend_type} '
                      f'from user_id={user_id}')
                migrated_backends.add(key)

        # Step 4: Create Hostname records from events table
        events_inspector = db.inspect(db.get_engine(bind_key='events'))
        if 'events' in events_inspector.get_table_names():
            events_session = db.session
            rows = events_session.execute(db.text(
                "SELECT DISTINCT user_id, hostname FROM events "
                "WHERE hostname IS NOT NULL AND hostname != ''"
            )).fetchall()

            hostname_count = 0
            for user_id, hostname_str in rows:
                hostname_lower = hostname_str.lower()
                # Find matching domain
                matched_domain = None
                for dname, dobj in domain_objs.items():
                    if hostname_lower.endswith(dname):
                        if matched_domain is None or len(dname) > len(matched_domain.name):
                            matched_domain = dobj
                if not matched_domain:
                    print(f'  WARNING: Cannot map hostname "{hostname_str}" '
                          f'(user_id={user_id}) to any domain — skipping')
                    continue

                existing = Hostname.query.filter_by(name=hostname_lower).first()
                if not existing:
                    hn = Hostname(name=hostname_lower, domain_id=matched_domain.id, user_id=user_id)
                    db.session.add(hn)
                    hostname_count += 1

            print(f'Created {hostname_count} hostname(s) from events history.')

        db.session.commit()

        # Summary
        print('\nMigration complete:')
        print(f'  Domains: {len(domain_objs)}')
        print(f'  Backends: {len(db_backend_objs)}')
        print(f'  Migrated credential sets: {len(migrated_backends)}')

        print('\nYou can now safely drop the old tables:')
        print("  DROP TABLE IF EXISTS backend_configs;")
        print("  (old backend_configs — new ones are in the same table with domain_backend_id)")
        print("  DROP TABLE IF EXISTS user_domains;")


if __name__ == '__main__':
    main()
