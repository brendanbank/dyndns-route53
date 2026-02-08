# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Dynamic DNS web service that implements the DynDNS v2 protocol (`/nic/update` endpoint). It accepts DNS update requests via HTTP and updates records through pluggable backends: AWS Route53 (via boto3) and BIND nsupdate (via dnspython TSIG). Designed to work with OPNsense's DynDNS client.

## Running

**Docker (production):**
```
docker compose up --build
```
Traefik handles TLS; serves on HTTPS (port 443 by default, configurable via `HTTPS_PORT`).

**Local development:**
```
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python wsgi.py
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

`dyndns.py` is the Flask app with a single endpoint `GET /nic/update`. It authenticates via HTTP Basic Auth (or query params), validates the request, then delegates to an account backend to create DNS records.

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

## Environment Variables

All configured in `.env` (loaded via python-dotenv):

**Required (all backends):** `USERNAME`, `PASSWORD` (bcrypt hash), `DOMAINS` (comma-separated)

**AWS backend:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`

**nsupdate backend:** `NSUPDATE_KEY`, `NSUPDATE_ALGO`, `NSUPDATE_SECRET`, `NSUPDATE_NAMESERVER`

**Traefik:** `TRAEFIK_HOSTNAME`, `LETSENCRYPT_EMAIL`, `LETSENCRYPT_CASERVER`, `HTTP_PORT`, `HTTPS_PORT`

**Optional:** `DEBUG=DEBUG` for verbose logging, `HOST` (used by test scripts)

## Deployment

Docker Compose runs Traefik (TLS via Let's Encrypt) in front of the Flask/uWSGI container. Docker image is based on `tiangolo/uwsgi-nginx-flask:python3.12`. The Dockerfile copies `dyndns.py` as `main.py` (required by the base image). uWSGI config is in `uwsgi.ini`. Compose config sends logs to Loki.
