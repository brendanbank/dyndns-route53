# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Dynamic DNS web service that implements the DynDNS v2 protocol (`/nic/update` endpoint). It accepts DNS update requests via HTTP and updates records through pluggable backends: AWS Route53 (via boto3) and BIND nsupdate (via dnspython TSIG). Designed to work with OPNsense's DynDNS client and other DynDNS v2-compatible clients.

## Running

**Docker (pre-built image):**
```
docker compose up -d
```
Pulls `ghcr.io/brendanbank/dyndns-route53:latest` from GHCR. Traefik handles TLS; serves on HTTPS (port 443 by default, configurable via `HTTPS_PORT`).

**Docker (local build):**
```
docker compose up --build
```

**Local development:**
```
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python dyndns.py
```
Runs Flask dev server on `0.0.0.0:8080`.

**Testing an update:**
```
./tests/dyndns-client-test.sh  # tests against HOST from .env
```

**Generate a bcrypt password hash:**
```
python3 getpwd.py [optional-plaintext-password]
```

## Architecture

### Request Flow

`dyndns.py` is the Flask app with a single endpoint `GET /nic/update`. It authenticates via HTTP Basic Auth (or query params), validates the request, then delegates to an account backend to create DNS records. Responses follow the DynDNS v2 protocol: `good <IP>`, `nochg <IP>`, `badauth`, `notfqdn`, `nohost`, `911`, with one line per hostname.

### Plugin System (`lib/`)

- `lib/accounts.py` — `BaseAccount` base class and `AccountFactory`. The factory auto-discovers account classes from `lib/account/*.py` at startup via `importlib`. Each backend subclass defines `_services` (list of service names), `match()`, and `createrecords()`.
- `lib/account/aws.py` — `AWS` class: updates Route53 via boto3. Fetches hosted zones from AWS and maps hostnames to zone IDs.
- `lib/account/nsupdate.py` — `nsupdate` class: updates BIND DNS via TSIG-authenticated `dns.update`/`dns.query.tcp`.

To add a new DNS backend: create a new file in `lib/account/`, subclass `BaseAccount`, implement `_services`, `match()`, `known_services()`, and `createrecords()`. It will be auto-registered.

### Key behaviors

- Before updating DNS, `check_hostnameon_server()` resolves the current record against the authoritative nameserver. If the IP hasn't changed, the update is skipped.
- The `DOMAINS` env var (comma-separated) restricts which domains can be updated. AWS backend additionally fetches hosted zones from Route53.
- The `updatetype` query parameter selects the backend (default: `aws`).
- Passwords are stored as bcrypt hashes in `.env` (`PASSWORD`); `PASSWORD_CT` is the cleartext for test scripts.
- Authentication uses constant-time comparison (`hmac.compare_digest`) to prevent timing attacks.
- Werkzeug's `ProxyFix` middleware (`x_for=1`) ensures `request.remote_addr` reflects the real client IP from Traefik's `X-Forwarded-For` header.

## Environment Variables

All configured in `.env` (loaded via python-dotenv):

**Required (all backends):** `USERNAME`, `PASSWORD` (bcrypt hash), `DOMAINS` (comma-separated)

**AWS backend:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`

**nsupdate backend:** `NSUPDATE_KEY`, `NSUPDATE_ALGO`, `NSUPDATE_SECRET`, `NSUPDATE_NAMESERVER`

**Traefik:** `TRAEFIK_HOSTNAME`, `LETSENCRYPT_EMAIL`, `LETSENCRYPT_CASERVER`, `HTTP_PORT`, `HTTPS_PORT`

**Optional:** `DEBUG=DEBUG` for verbose logging, `HOST` (used by test scripts)

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

- `.env` contains secrets and is in `.gitignore` — never commit it
- If credentials are accidentally committed, rotate them immediately and rewrite git history (`git checkout --orphan` + force push)
- GHCR package visibility is independent of repo visibility
- Query parameter authentication is supported but logs a warning — prefer HTTP Basic Auth
- Gunicorn access log excludes query strings to prevent password leakage
