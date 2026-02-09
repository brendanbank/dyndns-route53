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

from config import Config
from models import db, User, Event
from auth import login_manager, authenticate_dyndns_user
from lib import log, AccountFactory


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

        # Create admin user on first boot if none exists
        if not app.config.get('TESTING'):
            admin = User.query.filter_by(role='admin').first()
            if not admin:
                admin_password = os.environ.get('ADMIN_PASSWORD')
                if not admin_password:
                    raise RuntimeError(
                        'No admin user exists and ADMIN_PASSWORD is not set. '
                        'Set ADMIN_PASSWORD in .env to a bcrypt hash. '
                        'Generate one with: python3 getpwd.py'
                    )
                admin = User(
                    username='admin',
                    password_hash=admin_password,
                    role='admin',
                    is_active=True,
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
        db.session.commit()
    except Exception as e:
        log.error(f'Failed to log event: {e}')
        db.session.rollback()


def find_user_domain(user, hostname, backend_type):
    """Find the UserDomain that matches a hostname for a given backend type.
    Returns the UserDomain whose domain_name is a suffix of hostname."""
    best_match = None
    for ud in user.domains:
        if ud.backend_type != backend_type:
            continue
        if hostname.lower().endswith(ud.domain_name.lower()):
            # Pick the longest matching domain (most specific)
            if best_match is None or len(ud.domain_name) > len(best_match.domain_name):
                best_match = ud
    return best_match


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

    updatetype = request.args.get("updatetype", default="aws")

    log.info(f'received request from {ip} to host: {request.host}  url: {url}')

    if not myip or not hostnames:
        log.critical(f'invalid IP address {myip} or hostnames {hostnames}')
        return httpReply("911")

    log.info(f'received request from user {username} for myip = {myip}, hostname = {hostnames}')

    # Use a temporary account to validate IP and hostnames
    temp_account = Accounts.get({"service": updatetype, "domains": [], "credentials": {}})
    if not temp_account:
        log.critical('invalid updatetype')
        return httpReply("badauth")

    validated_ip = temp_account.getip(myip)
    if not validated_ip:
        log.critical(f'invalid IP address {myip}')
        return httpReply("911")

    ipType = temp_account.getiptype(validated_ip)
    if not ipType:
        log.critical(f'invalid IP address {validated_ip}')
        return httpReply("911")

    hostnamesObj = temp_account.isvalidhostname(hostnames)
    if not hostnamesObj:
        log.critical(f'invalid hostname {hostnames}')
        return httpReply("notfqdn")

    # Process each hostname against its own domain + credentials
    lines = []
    for hostname in hostnamesObj:
        ud = find_user_domain(user, hostname, updatetype)
        if not ud:
            log.warning(f'hostname {hostname} does not match any domain for user {username} backend {updatetype}')
            lines.append(f"nohost {validated_ip}")
            log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                      backend_type=updatetype, response='nohost')
            continue

        creds = ud.get_credentials()
        if not creds:
            log.warning(f'no credentials for domain {ud.domain_name} backend {updatetype} user {username}')
            lines.append(f"911 {validated_ip}")
            log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                      backend_type=updatetype, response='911')
            continue

        account_dict = {
            "service": updatetype,
            "domains": [ud.domain_name],
            "credentials": creds,
        }
        account = Accounts.get(account_dict)
        if not account:
            lines.append(f"911 {validated_ip}")
            log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                      backend_type=updatetype, response='911')
            continue

        hostname_zones = account.hostnameperzone([hostname])
        if not hostname_zones:
            lines.append(f"nohost {validated_ip}")
            log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                      backend_type=updatetype, response='nohost')
            continue

        results = account.createrecords(str(validated_ip), hostname_zones, rtype=ipType)
        status = results.get(hostname, "dnserr") if results else "dnserr"
        lines.append(f"{status} {validated_ip}")
        log_event(user, 'dns_update', hostname=hostname, ip_address=str(validated_ip),
                  backend_type=updatetype, response=status)

    return httpReply("\n".join(lines))


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8080)
