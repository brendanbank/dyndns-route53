# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Dynamic DNS web service that implements the DynDNS v2 protocol (`/nic/update` and `/nic/delete` endpoints). It accepts DNS update and delete requests via HTTP and manages records through pluggable backends: AWS Route53 (via boto3), BIND nsupdate (via dnspython TSIG), and Hetzner Cloud DNS (via REST API). Designed to work with OPNsense's DynDNS client and other DynDNS v2-compatible clients.

Supports multi-user operation with global domains (admin-managed), per-domain backends with shared credentials, user-owned hostnames, and a Bootstrap 5 web UI for administration.

## Running

**Docker (pre-built image):**
```
docker compose up -d
```
Pulls `ghcr.io/brendanbank/dyndns-route53:latest` from GHCR. Traefik handles TLS; serves on HTTPS (port 443 by default, configurable via `HTTPS_PORT`). Database and admin user are created automatically on first boot.

**Docker (local build):**
```
docker compose up --build
```

**Local development:**
```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env   # edit with SECRET_KEY, FERNET_KEY, ADMIN_PASSWORD
.venv/bin/python dyndns.py
```
Runs Flask dev server on `0.0.0.0:8080`. Web UI at `http://localhost:8080/admin/login`.

**Testing an update:**
```
./tests/dyndns-client-test.sh  # tests against HOST from .env
```

**Generate a bcrypt password hash:**
```
python3 getpwd.py [optional-plaintext-password]
```

**Backup databases:**
```
./scripts/backup.sh                    # Docker (default)
./scripts/backup.sh --local            # local install
./scripts/backup.sh --restore ./backups/  # restore from latest backup
```

## Architecture

### Application Factory

`dyndns.py` uses Flask's application factory pattern (`create_app()`). It initializes:
- Flask-SQLAlchemy (`db`) with dual binds: main DB (`instance/dyndns.db`) and events DB (`instance/events.db`)
- Flask-Login for web session auth
- Flask-WTF CSRF protection (exempted for `/nic/update` and `/nic/delete`)
- Two blueprints: `nic_update_bp` (DynDNS API) and `web_bp` (admin UI)

Gunicorn uses the factory syntax `dyndns:create_app()` to create the app at worker startup.

### Data Model

```
User 1---* Hostname *---* DomainBackend *---1 Domain
                              1---* BackendConfig
```

- **Domain** — global zone managed by admin (e.g. `dyn.bgwlan.nl`). Has backends and hostnames.
- **DomainBackend** — backend config for a domain (aws/nsupdate/hetzner). Unique constraint on `(domain_id, backend_type)`. Has credentials via BackendConfig.
- **Hostname** — user-owned FQDN, globally unique (e.g. `myhost.dyn.bgwlan.nl`). Belongs to one domain and one user. Has optional many-to-many relationship with backends via `hostname_backends` table.
- **BackendConfig** — per-backend encrypted key-value pairs (e.g. `aws_access_key_id`). FK to `domain_backends`. Values Fernet-encrypted.
- **User** — username, bcrypt password hash, role (`admin`/`user`), active flag, TOTP secret. Has hostnames.
- **Event** — DNS update audit log (separate SQLite bind `events`). Records user, hostname, IP, backend, response.

### Request Flow

`GET /nic/update` authenticates via HTTP Basic Auth (or query params) against the `users` table. For each hostname in the request:
1. Look up `Hostname` record by exact name match + user ownership
2. If not found → `nohost`
3. Get backends for the hostname via `Hostname.get_backends()` — returns hostname-specific backends if configured, otherwise all domain backends
4. For each backend: get Fernet-encrypted credentials, create account via `AccountFactory`, call `createrecords()`
5. Log one `Event` per backend attempt
6. Aggregate result: `good` if any backend succeeded, `nochg` if all unchanged, error otherwise

The `updatetype` parameter is deprecated and ignored — all backends for the domain are updated automatically.

`GET /nic/delete` uses the same auth and hostname lookup. If `myip` is provided, only the matching record type (A or AAAA) is deleted; if omitted, both A and AAAA records are deleted. Calls `deleterecords()` on each backend. Events are logged with `event_type='dns_delete'`.

### Plugin System (`lib/`)

- `lib/accounts.py` — `BaseAccount` base class and `AccountFactory`. The factory auto-discovers account classes from `lib/account/*.py` at startup via `importlib`. Each backend subclass defines `_services` (list of service names), `match()`, `createrecords()`, and `deleterecords()`.
- `lib/account/aws.py` — `AWS` class: updates/deletes Route53 records via boto3. Reads credentials from `account['credentials']` dict (DB-backed) with env var fallback.
- `lib/account/nsupdate.py` — `nsupdate` class: updates/deletes BIND DNS records via TSIG-authenticated `dns.update`/`dns.query.tcp`. Same credential pattern.
- `lib/account/hetzner.py` — `Hetzner` class: updates/deletes DNS records via the Hetzner Cloud API (`api.hetzner.cloud/v1`). Uses Bearer token auth and RRSet-based operations (records identified by `name/type`). Updates use the `set_records` action endpoint. Same credential pattern (`HETZNER_API_TOKEN` env var fallback).

Backend plugins accept domains from `account['domains']` and credentials from `account['credentials']`, falling back to environment variables for backward compatibility.

To add a new DNS backend: create a new file in `lib/account/`, subclass `BaseAccount`, implement `_services`, `match()`, `known_services()`, `_get_credentials()`, `createrecords()`, and `deleterecords()`. It will be auto-registered.

### Web UI (`web_routes.py`, `templates/`)

Bootstrap 5 dark-theme UI at `/admin/`. Flask-Login session auth.

**Admin routes:** user CRUD, global domain CRUD, per-domain backend management + credential config, per-user hostname management, event log viewer.
**User self-service:** register/remove hostnames under available domains, browse own event history, change password.

### Auth (`auth.py`)

Dual auth: `/nic/update` uses HTTP Basic Auth; web UI uses Flask-Login sessions with mandatory TOTP two-factor authentication. Both validate passwords against the same `users` table via `authenticate_dyndns_user()`. Admin-only routes use `@admin_required` decorator.

Web login is a multi-step flow: password verification stores `pending_2fa_user_id` in the session, then redirects to TOTP verification (or TOTP setup for first-time users). The user is not fully authenticated until the TOTP step passes. The `/nic/update` DynDNS API is unaffected by 2FA — DynDNS clients use HTTP Basic Auth only.

### Key behaviors

- Before updating DNS, `check_hostnameon_server()` resolves the current record against the authoritative nameserver. If the IP hasn't changed, the update is skipped.
- Hostnames are globally unique — each hostname belongs to exactly one user and one domain.
- Users register hostnames under admin-created domains. When updated via `/nic/update`, all backends configured for the hostname's domain are called.
- Passwords are stored as bcrypt hashes in the `users` table.
- Authentication uses constant-time comparison (`hmac.compare_digest`) to prevent timing attacks.
- Backend credentials are Fernet-encrypted at rest per domain backend. Loss of `FERNET_KEY` = loss of all stored credentials.
- Werkzeug's `ProxyFix` middleware (`x_for=1`) ensures `request.remote_addr` reflects the real client IP from Traefik's `X-Forwarded-For` header.
- SQLite WAL mode enabled for concurrent read access under gunicorn workers.

## Environment Variables

Configured in `.env` (loaded via python-dotenv):

**Required:**
- `SECRET_KEY` — Flask session secret
- `FERNET_KEY` — Fernet encryption key for backend credentials in database
- `ADMIN_PASSWORD` — password for the initial admin user. Accepts plaintext (hashed automatically at boot) or a pre-computed bcrypt hash (detected by `$2b$`/`$2a$`/`$2y$` prefix). Required on first boot when no admin exists; app will refuse to start without it.

**Optional:**
- `ADMIN_TOTP_SECRET` — base32 TOTP secret for admin 2FA (generate with `python3 -c "import pyotp; print(pyotp.random_base32())"`)
- `DEBUG=DEBUG` — verbose logging

**Traefik:** `TRAEFIK_HOSTNAME`, `LETSENCRYPT_EMAIL`, `LETSENCRYPT_CASERVER`, `HTTP_PORT`, `HTTPS_PORT`

**Legacy (backward compat / migration):** `USERNAME`, `PASSWORD`, `DOMAINS`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `NSUPDATE_KEY`, `NSUPDATE_ALGO`, `NSUPDATE_SECRET`, `NSUPDATE_NAMESERVER`, `HETZNER_API_TOKEN`

## CI/CD

GitHub Actions workflows:

### `docker-publish.yml` — Test, build, and publish

**Triggers:**
- Push tag `v*` → runs tests, builds multi-platform image (`linux/amd64`, `linux/arm64`), pushes to GHCR with semver tags, runs Trivy vulnerability scan, creates GitHub Release
- Pull request to `main` → runs tests, builds single-platform image (`linux/amd64`) with `load: true`, runs Trivy scan, uploads SARIF to Security tab (no push to registry)

**Test job** (runs before Docker build): `ruff check .` + `python -m pytest tests/ -v`. If lint or tests fail, the build is skipped.

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

Docker Compose runs Traefik (TLS via Let's Encrypt HTTP-01 challenge) in front of the Flask/gunicorn container. Docker image is based on `python:3.13-slim` with gunicorn as the WSGI server. Gunicorn uses the factory syntax `dyndns:create_app()` to create the app at worker startup.

The `instance/` directory (SQLite databases) is persisted via a Docker named volume (`dyndns-data:/app/instance`). Use `scripts/backup.sh` to back up and restore these databases safely (WAL-mode safe, works while the app is running).

Traefik and the web container share a `web-network` bridge network. To preserve real client IPs, the Docker daemon must have `"userland-proxy": false` in `/etc/docker/daemon.json` (Docker's default userland-proxy rewrites source IPs to the bridge gateway). With this setting, iptables NAT preserves source IPs and Traefik correctly populates `X-Forwarded-For`. Port mapping uses `${HTTP_PORT:-80}:80` and `${HTTPS_PORT:-443}:443`.

Gunicorn access log uses a custom format with `%(U)s` (path only) instead of `%(r)s` (full request line) to prevent passwords in query parameters from appearing in logs.

There are two compose files:
- `compose.yaml` — for development. Has `image:` + `build:` (pull uses GHCR, `--build` builds locally). Uses bind-mount for certs, staging ACME server, Loki logging.
- `compose.example.yaml` — standalone file for end users. No `build:`, named volume for certs, production ACME server, no Loki. Linked from GitHub release notes.

## Testing

**Pytest (107 tests):**
```
python -m pytest tests/ -v
```

**Ruff lint:**
```
ruff check .
```

**Deployment smoke test:**
```
# Production (HTTPS)
./tests/smoke_test.sh --host dyndns.example.com --user admin --pass secret

# Local Flask dev server (HTTP)
./tests/smoke_test.sh --http --host localhost:8080 --user admin --pass secret

# Local Docker with Traefik (HTTPS, resolve hostname to localhost)
./tests/smoke_test.sh --host dyndns.example.com:9443 --resolve 127.0.0.1 --user admin --pass secret
```

**DNS smoke test (real DNS update + delete against live backends):**
```
# Load credentials and run (requires .env.smoketest with backend creds)
source .env.smoketest && ./tests/smoke_test_dns.sh

# Or pass all arguments explicitly
./tests/smoke_test_dns.sh --host localhost:8080 --http \
    --user admin --pass secret \
    --hostname test.dyn.example.com --myip 203.0.113.42 \
    --nameserver 8.8.8.8
```
Creates an A record, verifies it via DNS lookup, confirms `nochg` on duplicate update, deletes the record, verifies deletion, and confirms `nochg` on duplicate delete. Always cleans up test records on exit (even on failure).

**Manual curl against local Traefik** (must pass `Host` header since Traefik routes by hostname):
```
# Update a record
curl -s -k -H "Host: ${TRAEFIK_HOSTNAME}" -u ${USERNAME}:${PASSWORD} \
  "https://localhost:${HTTPS_PORT}/nic/update?hostname=test.dyn.bgwlan.nl&myip=203.0.113.1"

# Delete a record (both A and AAAA)
curl -s -k -H "Host: ${TRAEFIK_HOSTNAME}" -u ${USERNAME}:${PASSWORD} \
  "https://localhost:${HTTPS_PORT}/nic/delete?hostname=test.dyn.bgwlan.nl"

# Delete only the A record matching a specific IP
curl -s -k -H "Host: ${TRAEFIK_HOSTNAME}" -u ${USERNAME}:${PASSWORD} \
  "https://localhost:${HTTPS_PORT}/nic/delete?hostname=test.dyn.bgwlan.nl&myip=203.0.113.1"
```
Expected update response: `good 203.0.113.1` (record created/updated) or `nochg 203.0.113.1` (IP unchanged).
Expected delete response: `good` (record deleted) or `nochg` (record didn't exist).

## Security Notes

- `.env` contains secrets (`SECRET_KEY`, `FERNET_KEY`) and is in `.gitignore` — never commit it
- `instance/` contains SQLite databases with encrypted credentials — in `.gitignore`, persisted via Docker volume
- If `FERNET_KEY` is lost, all encrypted backend credentials in the database are unrecoverable
- If credentials are accidentally committed, rotate them immediately and rewrite git history (`git checkout --orphan` + force push)
- GHCR package visibility is independent of repo visibility
- Query parameter authentication is supported but logs a warning — prefer HTTP Basic Auth
- Gunicorn access log excludes query strings to prevent password leakage
- CSRF protection enabled for all web forms; `/nic/update` and `/nic/delete` are exempt (use Basic Auth)
