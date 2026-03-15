# BSD 3-Clause License
#
# Copyright (c) 2023, Brendan Bank
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


from flask import Flask, request, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import os
from datetime import datetime, timedelta, timezone

import bcrypt as _bcrypt

from config import Config
from models import db, User, Hostname, Event
from auth import login_manager, authenticate_dyndns_user
from lib import log, AccountFactory
from lib.accounts import BaseAccount


def create_app(config_class=None):
    app = Flask(__name__)
    app.config.from_object(config_class or Config)

    # Ensure instance directory exists
    os.makedirs(os.path.join(app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '').rsplit('/', 1)[0]), exist_ok=True)

    # Enable WAL mode for better concurrent access
    def set_wal_mode(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute('PRAGMA journal_mode=WAL')
        cursor.close()

    db.init_app(app)
    login_manager.init_app(app)

    from sqlalchemy import event as sa_event
    with app.app_context():
        sa_event.listen(db.engine, 'connect', set_wal_mode)
        for bind_key, engine in db.engines.items():
            if bind_key is not None:
                sa_event.listen(engine, 'connect', set_wal_mode)
        db.create_all()

        # One-time migration: add totp_secret column to users table
        try:
            db.session.execute(db.text('ALTER TABLE users ADD COLUMN totp_secret TEXT'))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # One-time migration: add web_login column to users table
        try:
            db.session.execute(db.text('ALTER TABLE users ADD COLUMN web_login BOOLEAN NOT NULL DEFAULT 0'))
            db.session.commit()
            # Enable web login for existing admin users
            db.session.execute(db.text("UPDATE users SET web_login = 1 WHERE role = 'admin'"))
            db.session.commit()
        except Exception:
            db.session.rollback()

        # One-time migration: populate hostname_backends for existing hostnames
        # This ensures all existing hostnames have all their domain backends enabled
        try:
            hostnames_without_backends = Hostname.query.filter(~Hostname.backends.any()).all()
            if hostnames_without_backends:
                for hn in hostnames_without_backends:
                    # Enable all domain backends for this hostname
                    hn.backends = list(hn.domain.backends)
                db.session.commit()
                log.info(f'Migration: enabled all backends for {len(hostnames_without_backends)} existing hostname(s).')
        except Exception as e:
            db.session.rollback()
            log.warning(f'Migration hostname_backends skipped: {e}')

        # Create admin user on first boot if none exists
        if not app.config.get('TESTING'):
            admin = User.query.filter_by(role='admin').first()
            if not admin:
                admin_password = os.environ.get('ADMIN_PASSWORD')
                if not admin_password:
                    raise RuntimeError(
                        'No admin user exists and ADMIN_PASSWORD is not set. '
                        'Set ADMIN_PASSWORD in .env (plaintext or bcrypt hash).'
                    )
                # Accept plaintext or pre-hashed bcrypt passwords
                if admin_password.startswith(('$2b$', '$2a$', '$2y$')):
                    password_hash = admin_password
                else:
                    password_hash = _bcrypt.hashpw(
                        admin_password.encode('utf8'), _bcrypt.gensalt()
                    ).decode()
                admin = User(
                    username='admin',
                    password_hash=password_hash,
                    role='admin',
                    is_active=True,
                    web_login=True,
                )
                admin_totp = os.environ.get('ADMIN_TOTP_SECRET')
                if admin_totp:
                    admin.set_totp_secret(admin_totp)
                db.session.add(admin)
                db.session.commit()
                log.info('Admin user created from ADMIN_PASSWORD env var.')

    # Proxy fix for Traefik
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Register web UI blueprint
    from web_routes import web_bp
    app.register_blueprint(web_bp)

    # Exempt /nic/update from CSRF
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)
    csrf.exempt(nic_update_bp)

    app.register_blueprint(nic_update_bp)

    return app


# Blueprint for the DynDNS update endpoint
from flask import Blueprint  # noqa: E402
nic_update_bp = Blueprint('nic_update', __name__)

Accounts = AccountFactory()


def httpReply(text, returncode=200):
    response = make_response(text, returncode)
    response.mimetype = "text/plain"
    return response


def log_event(user, event_type, hostname=None, ip_address=None, backend_type=None, response=None, detail=None):
    try:
        ev = Event(
            user_id=user.id,
            username=user.username,
            event_type=event_type,
            hostname=hostname,
            ip_address=ip_address,
            backend_type=backend_type,
            response=response,
            detail=detail,
        )
        db.session.add(ev)
        # Prune events older than 24 hours
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        Event.query.filter(Event.created_at < cutoff).delete()
        db.session.commit()
    except Exception as e:
        log.error(f'Failed to log event: {e}')
        db.session.rollback()


def find_hostname(user, hostname_str):
    """Find a Hostname record owned by the user matching the exact hostname string."""
    return Hostname.query.filter_by(name=hostname_str.lower(), user_id=user.id).first()


@nic_update_bp.route("/nic/update")
def updateDydns():
    myip = request.args.get("myip")

    hostnames = request.args.get("hostname")

    auth = request.authorization

    if (auth):
        username = auth.username
        password = auth.password
    else:
        username = request.args.get("username")
        password = request.args.get("password")
        if username or password:
            log.warning('credentials passed via query parameters - use HTTP Basic Auth instead')

    url = re.sub(r"password=[^\&]*", "password=********", request.url)
    ip = request.remote_addr

    if not myip:
        myip = ip

    # Authenticate against database
    user = authenticate_dyndns_user(username, password)
    if not user:
        log.critical('invalid username or password')
        return httpReply("badauth")

    updatetype = request.args.get("updatetype")
    if updatetype:
        log.warning(f'updatetype parameter is deprecated and ignored (was: {updatetype})')

    log.info(f'received request from {ip} to host: {request.host}  url: {url}')

    if not myip or not hostnames:
        log.critical(f'invalid IP address {myip} or hostnames {hostnames}')
        return httpReply("911")

    log.info(f'received request from user {username} for myip = {myip}, hostname = {hostnames}')

    # Validate IP and hostnames using BaseAccount static methods
    validated_ip = BaseAccount.getip(myip)
    if not validated_ip:
        log.critical(f'invalid IP address {myip}')
        return httpReply("911")

    ipType = BaseAccount.getiptype(validated_ip)
    if not ipType:
        log.critical(f'invalid IP address {validated_ip}')
        return httpReply("911")

    hostnamesObj = BaseAccount.isvalidhostname(hostnames)
    if not hostnamesObj:
        log.critical(f'invalid hostname {hostnames}')
        return httpReply("notfqdn")

    # Process each hostname against all its domain backends
    lines = []
    for hostname in hostnamesObj:
        hn = find_hostname(user, hostname)
        if not hn:
            log.warning(f'hostname {hostname} not registered for user {username}')
            lines.append(f"nohost {validated_ip}")
            log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                      backend_type=None, response='nohost')
            continue

        domain = hn.domain
        backends = hn.get_backends()

        if not backends:
            log.warning(f'no backends configured for hostname {hostname}')
            lines.append(f"911 {validated_ip}")
            log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                      backend_type=None, response='911')
            continue

        # Try all backends for this hostname (hostname-specific or all domain backends)
        results = []
        for db_backend in backends:
            creds = db_backend.get_credentials()
            if not creds:
                log.warning(f'no credentials for domain {domain.name} backend {db_backend.backend_type}')
                log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                          backend_type=db_backend.backend_type, response='911')
                results.append('911')
                continue

            account_dict = {
                "service": db_backend.backend_type,
                "domains": [domain.name],
                "credentials": creds,
            }
            account = Accounts.get(account_dict)
            if not account:
                log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                          backend_type=db_backend.backend_type, response='911')
                results.append('911')
                continue

            hostname_zones = account.hostnameperzone([hostname])
            if not hostname_zones:
                log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                          backend_type=db_backend.backend_type, response='nohost')
                results.append('nohost')
                continue

            update_results = account.createrecords(str(validated_ip), hostname_zones, rtype=ipType)
            status = update_results.get(hostname, "dnserr") if update_results else "dnserr"
            log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                      backend_type=db_backend.backend_type, response=status)
            results.append(status)

        # Aggregate: good if any good, nochg if all nochg, else first error
        if 'good' in results:
            lines.append(f"good {validated_ip}")
        elif all(r == 'nochg' for r in results):
            lines.append(f"nochg {validated_ip}")
        else:
            # Return the first non-nochg status
            error_status = next((r for r in results if r not in ('good', 'nochg')), 'dnserr')
            lines.append(f"{error_status} {validated_ip}")

    return httpReply("\n".join(lines))


@nic_update_bp.route("/nic/delete")
def deleteDyndns():
    myip = request.args.get("myip")

    hostnames = request.args.get("hostname")

    auth = request.authorization

    if (auth):
        username = auth.username
        password = auth.password
    else:
        username = request.args.get("username")
        password = request.args.get("password")
        if username or password:
            log.warning('credentials passed via query parameters - use HTTP Basic Auth instead')

    url = re.sub(r"password=[^\&]*", "password=********", request.url)
    ip = request.remote_addr

    # Authenticate against database
    user = authenticate_dyndns_user(username, password)
    if not user:
        log.critical('invalid username or password')
        return httpReply("badauth")

    log.info(f'received delete request from {ip} to host: {request.host}  url: {url}')

    if not hostnames:
        log.critical('missing hostname parameter')
        return httpReply("911")

    log.info(f'received delete request from user {username} for hostname = {hostnames}, myip = {myip}')

    # Determine which record types to delete
    rtype = None
    if myip:
        validated_ip = BaseAccount.getip(myip)
        if not validated_ip:
            log.critical(f'invalid IP address {myip}')
            return httpReply("911")
        rtype = BaseAccount.getiptype(validated_ip)
        if not rtype:
            log.critical(f'invalid IP address {validated_ip}')
            return httpReply("911")

    hostnamesObj = BaseAccount.isvalidhostname(hostnames)
    if not hostnamesObj:
        log.critical(f'invalid hostname {hostnames}')
        return httpReply("notfqdn")

    # Process each hostname against all its domain backends
    lines = []
    for hostname in hostnamesObj:
        hn = find_hostname(user, hostname)
        if not hn:
            log.warning(f'hostname {hostname} not registered for user {username}')
            lines.append("nohost")
            log_event(user, 'dns_delete', hostname=hostname,
                      ip_address=myip, backend_type=None, response='nohost')
            continue

        domain = hn.domain
        backends = hn.get_backends()

        if not backends:
            log.warning(f'no backends configured for hostname {hostname}')
            lines.append("911")
            log_event(user, 'dns_delete', hostname=hostname,
                      ip_address=myip, backend_type=None, response='911')
            continue

        # Try all backends for this hostname (hostname-specific or all domain backends)
        results = []
        for db_backend in backends:
            creds = db_backend.get_credentials()
            if not creds:
                log.warning(f'no credentials for domain {domain.name} backend {db_backend.backend_type}')
                log_event(user, 'dns_delete', hostname=hostname,
                          ip_address=myip, backend_type=db_backend.backend_type, response='911')
                results.append('911')
                continue

            account_dict = {
                "service": db_backend.backend_type,
                "domains": [domain.name],
                "credentials": creds,
            }
            account = Accounts.get(account_dict)
            if not account:
                log_event(user, 'dns_delete', hostname=hostname,
                          ip_address=myip, backend_type=db_backend.backend_type, response='911')
                results.append('911')
                continue

            hostname_zones = account.hostnameperzone([hostname])
            if not hostname_zones:
                log_event(user, 'dns_delete', hostname=hostname,
                          ip_address=myip, backend_type=db_backend.backend_type, response='nohost')
                results.append('nohost')
                continue

            delete_results = account.deleterecords(hostname_zones, rtype=rtype)
            status = delete_results.get(hostname, "dnserr") if delete_results else "dnserr"
            log_event(user, 'dns_delete', hostname=hostname,
                      ip_address=myip, backend_type=db_backend.backend_type, response=status)
            results.append(status)

        # Aggregate: good if any good, nochg if all nochg, else first error
        if 'good' in results:
            lines.append("good")
        elif all(r == 'nochg' for r in results):
            lines.append("nochg")
        else:
            error_status = next((r for r in results if r not in ('good', 'nochg')), 'dnserr')
            lines.append(error_status)

    return httpReply("\n".join(lines))


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8080)
