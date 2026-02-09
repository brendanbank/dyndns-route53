# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Dynamic DNS web service that implements the DynDNS v2 protocol (`/nic/update` endpoint). It accepts DNS update requests via HTTP and updates records through pluggable backends: AWS Route53 (via boto3) and BIND nsupdate (via dnspython TSIG). Designed to work with OPNsense's DynDNS client and other DynDNS v2-compatible clients.

Supports multi-user operation with per-user domains, backend credentials (Fernet-encrypted in SQLite), and a Bootstrap 5 web UI for administration.

## Running

**Docker (pre-built image):**
```
docker compose up -d
docker compose exec web python3 init_db.py
```
Pulls `ghcr.io/brendanbank/dyndns-route53:latest` from GHCR. Traefik handles TLS; serves on HTTPS (port 443 by default, configurable via `HTTPS_PORT`).

**Docker (local build):**
```
docker compose up --build
docker compose exec web python3 init_db.py
```

**Local development:**
```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python init_db.py
.venv/bin/python dyndns.py
```
Runs Flask dev server on `0.0.0.0:8080`. Web UI at `http://localhost:8080/admin/login`.

**Migrate existing .env credentials to database:**
```
python3 migrate_env.py
```

**Testing an update:**
```
./tests/dyndns-client-test.sh  # tests against HOST from .env
```

**Generate a bcrypt password hash:**
```
python3 getpwd.py [optional-plaintext-password]
```

## Architecture

### Application Factory

`dyndns.py` uses Flask's application factory pattern (`create_app()`). It initializes:
- Flask-SQLAlchemy (`db`) with dual binds: main DB (`instance/dyndns.db`) and events DB (`instance/events.db`)
- Flask-Login for web session auth
- Flask-WTF CSRF protection (exempted for `/nic/update`)
- Two blueprints: `nic_update_bp` (DynDNS API) and `web_bp` (admin UI)

The module-level `app = create_app()` maintains compatibility with `gunicorn dyndns:app`.

### Request Flow

`GET /nic/update` authenticates via HTTP Basic Auth (or query params) against the `users` table, retrieves the user's per-backend domains and Fernet-encrypted credentials from the database, then delegates to the matching backend plugin. Responses follow the DynDNS v2 protocol: `good <IP>`, `nochg <IP>`, `badauth`, `notfqdn`, `nohost`, `911`, with one line per hostname. Each update is logged to the events database.

### Database Models (`models.py`)

- **User** — username, bcrypt password hash, role (`admin`/`user`), active flag. Integrates `flask_login.UserMixin`.
- **Domain** — allowed domain names (e.g. `dyn.bgwlan.nl`).
- **UserDomain** — maps users to domains with a backend type. Unique constraint on `(user_id, domain_id)`.
- **BackendConfig** — per-user, per-backend encrypted key-value pairs (e.g. `aws_access_key_id`). Values encrypted with Fernet.
- **Event** — DNS update audit log (separate SQLite bind `events`). Records user, hostname, IP, backend, response.

### Plugin System (`lib/`)

- `lib/accounts.py` — `BaseAccount` base class and `AccountFactory`. The factory auto-discovers account classes from `lib/account/*.py` at startup via `importlib`. Each backend subclass defines `_services` (list of service names), `match()`, and `createrecords()`.
- `lib/account/aws.py` — `AWS` class: updates Route53 via boto3. Reads credentials from `account['credentials']` dict (DB-backed) with env var fallback.
- `lib/account/nsupdate.py` — `nsupdate` class: updates BIND DNS via TSIG-authenticated `dns.update`/`dns.query.tcp`. Same credential pattern.

Backend plugins accept domains from `account['domains']` and credentials from `account['credentials']`, falling back to environment variables for backward compatibility.

To add a new DNS backend: create a new file in `lib/account/`, subclass `BaseAccount`, implement `_services`, `match()`, `known_services()`, `_get_credentials()`, and `createrecords()`. It will be auto-registered.

### Web UI (`web_routes.py`, `templates/`)

Bootstrap 5 dark-theme UI at `/admin/`. Flask-Login session auth.

**Admin routes:** user CRUD, domain CRUD, per-user domain assignment, per-user backend credential config, event log viewer.
**User self-service:** view assigned domains, browse own event history, change password.

### Auth (`auth.py`)

Dual auth: `/nic/update` uses HTTP Basic Auth; web UI uses Flask-Login sessions with mandatory TOTP two-factor authentication. Both validate passwords against the same `users` table via `authenticate_dyndns_user()`. Admin-only routes use `@admin_required` decorator.

Web login is a multi-step flow: password verification stores `pending_2fa_user_id` in the session, then redirects to TOTP verification (or TOTP setup for first-time users). The user is not fully authenticated until the TOTP step passes. The `/nic/update` DynDNS API is unaffected by 2FA — DynDNS clients use HTTP Basic Auth only.

### Key behaviors

- Before updating DNS, `check_hostnameon_server()` resolves the current record against the authoritative nameserver. If the IP hasn't changed, the update is skipped.
- Per-user domains (from `user_domains` table) restrict which domains each user can update. AWS backend additionally fetches hosted zones from Route53.
- The `updatetype` query parameter selects the backend (default: `aws`).
- Passwords are stored as bcrypt hashes in the `users` table.
- Authentication uses constant-time comparison (`hmac.compare_digest`) to prevent timing attacks.
- Backend credentials are Fernet-encrypted at rest. Loss of `FERNET_KEY` = loss of all stored credentials.
- Werkzeug's `ProxyFix` middleware (`x_for=1`) ensures `request.remote_addr` reflects the real client IP from Traefik's `X-Forwarded-For` header.
- SQLite WAL mode enabled for concurrent read access under gunicorn workers.

## Environment Variables

Configured in `.env` (loaded via python-dotenv):

**Required:**
- `SECRET_KEY` — Flask session secret
- `FERNET_KEY` — Fernet encryption key for backend credentials in database

**Optional:**
- `ADMIN_PASSWORD` — pre-hashed bcrypt password for initial admin (used by `init_db.py`)
- `ADMIN_TOTP_SECRET` — base32 TOTP secret for initial admin (used by `init_db.py`; generate with `python3 -c "import pyotp; print(pyotp.random_base32())"`)
- `DEBUG=DEBUG` — verbose logging

**Traefik:** `TRAEFIK_HOSTNAME`, `LETSENCRYPT_EMAIL`, `LETSENCRYPT_CASERVER`, `HTTP_PORT`, `HTTPS_PORT`

**Legacy (backward compat / migration):** `USERNAME`, `PASSWORD`, `DOMAINS`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `NSUPDATE_KEY`, `NSUPDATE_ALGO`, `NSUPDATE_SECRET`, `NSUPDATE_NAMESERVER`

## CI/CD

GitHub Actions workflows:

### `docker-publish.yml` — Docker image build and publish

**Triggers:**
- Push tag `v*` → builds multi-platform image (`linux/amd64`, `linux/arm64`), pushes to GHCR with semver tags, runs Trivy vulnerability scan, creates GitHub Release
- Pull request to `main` → builds single-platform image (`linux/amd64`) with `load: true`, runs Trivy scan, uploads SARIF to Security tab (no push to registry)

### `codeql.yml` — Static analysis

**Triggers:**
- Push tag `v*`, pull request to `main`, weekly schedule (Monday 6am), manual (`workflow_dispatch`)

### Dependabot

- `.github/dependabot.yml` — weekly updates for pip dependencies and GitHub Actions versions

**Releasing a new version:**
```
git tag v1.0.0 && git push origin v1.0.0
```

**GHCR package visibility** must be set to public manually via the GitHub web UI (Settings > Danger Zone > Change visibility) — the REST API does not support this for user-owned container packages.

## Deployment

Docker Compose runs Traefik (TLS via Let's Encrypt HTTP-01 challenge) in front of the Flask/gunicorn container. Docker image is based on `python:3.13-slim` with gunicorn as the WSGI server. Gunicorn imports `dyndns:app` directly.

The `instance/` directory (SQLite databases) is persisted via a Docker named volume (`dyndns-data:/app/instance`).

Traefik uses `network_mode: host` to preserve real client IPs (Docker's userland-proxy rewrites source IPs to the bridge gateway). With host networking, `ports:` is not used — entrypoint addresses use `${HTTP_PORT:-80}` and `${HTTPS_PORT:-443}` directly.

Gunicorn access log uses a custom format with `%(U)s` (path only) instead of `%(r)s` (full request line) to prevent passwords in query parameters from appearing in logs.

There are two compose files:
- `compose.yaml` — for development. Has `image:` + `build:` (pull uses GHCR, `--build` builds locally). Uses bind-mount for certs, staging ACME server, Loki logging.
- `compose.example.yaml` — standalone file for end users. No `build:`, named volume for certs, production ACME server, no Loki. Linked from GitHub release notes.

## Testing locally

When testing via curl against the local Traefik instance, you must pass the correct `Host` header since Traefik routes by hostname:
```
curl -s -k -H "Host: ${TRAEFIK_HOSTNAME}" -u ${USERNAME}:${PASSWORD_CT} \
  "https://localhost:${HTTPS_PORT}/nic/update?hostname=test.dyn.bgwlan.nl&myip=203.0.113.1"
```
Expected response: `good 203.0.113.1` (record created/updated) or `nochg 203.0.113.1` (IP unchanged).

## Security Notes

- `.env` contains secrets (`SECRET_KEY`, `FERNET_KEY`) and is in `.gitignore` — never commit it
- `instance/` contains SQLite databases with encrypted credentials — in `.gitignore`, persisted via Docker volume
- If `FERNET_KEY` is lost, all encrypted backend credentials in the database are unrecoverable
- If credentials are accidentally committed, rotate them immediately and rewrite git history (`git checkout --orphan` + force push)
- GHCR package visibility is independent of repo visibility
- Query parameter authentication is supported but logs a warning — prefer HTTP Basic Auth
- Gunicorn access log excludes query strings to prevent password leakage
- CSRF protection enabled for all web forms; `/nic/update` is exempt (uses Basic Auth)
