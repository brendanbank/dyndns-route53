# Installation & Configuration

## Docker Installation (Pre-built Image)

The easiest way to run dyndns-route53 is with the pre-built Docker image and the example compose file.

1. Download [`compose.example.yaml`](compose.example.yaml) and [`.env.example`](.env.example)
2. Copy and configure:
   ```bash
   cp compose.example.yaml compose.yaml
   cp .env.example .env
   # Edit .env — at minimum set SECRET_KEY, FERNET_KEY, TRAEFIK_HOSTNAME, LETSENCRYPT_EMAIL
   ```
3. Start the service:
   ```bash
   docker compose up -d
   ```
4. Initialize the database and create the admin user:
   ```bash
   docker compose exec web python3 init_db.py
   ```
   If `ADMIN_PASSWORD` is not set in `.env`, a random password is generated and printed. Save it.

Traefik handles TLS termination via Let's Encrypt. HTTP (port 80) redirects to HTTPS (port 443) automatically.

## Docker Installation (Local Build)

To build the image locally from source:

```bash
git clone git@github.com:brendanbank/dyndns-route53.git
cd dyndns-route53
cp .env.example .env   # edit with your settings
docker compose up --build
docker compose exec web python3 init_db.py
```

## Manual Installation

```bash
git clone git@github.com:brendanbank/dyndns-route53.git
cd dyndns-route53
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Initialize the database:

```bash
.venv/bin/python init_db.py
```

Run the development server:

```bash
.venv/bin/python dyndns.py
```

The Flask dev server listens on `0.0.0.0:8080`. The web UI is at `http://localhost:8080/admin/login`. For production, use Docker Compose with Traefik.

## First Login

1. Open the web UI at `https://your-hostname/admin/login`
2. Log in with `admin` and the password from `init_db.py`
3. You will be prompted to set up TOTP two-factor authentication (scan QR code with an authenticator app)
4. After 2FA setup, you'll be logged into the admin dashboard

## Configuration

All configuration is done through environment variables in a `.env` file. See [`.env.example`](.env.example) for a template.

### Required

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | Flask session secret (generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`) |
| `FERNET_KEY` | Encryption key for backend credentials (generate with `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`) |

### Optional

| Variable | Description |
|----------|-------------|
| `ADMIN_PASSWORD` | Pre-hashed bcrypt password for initial admin (used by `init_db.py`) |
| `ADMIN_TOTP_SECRET` | Pre-shared TOTP secret for admin 2FA (used by `init_db.py`) |
| `DEBUG` | Set to `DEBUG` for verbose logging |

### Traefik Reverse Proxy

| Variable | Description |
|----------|-------------|
| `TRAEFIK_HOSTNAME` | Domain name for the TLS certificate (e.g. `dyndns.example.com`) |
| `LETSENCRYPT_EMAIL` | Email address for Let's Encrypt registration |
| `LETSENCRYPT_CASERVER` | ACME CA server URL (see below) |
| `HTTP_PORT` | External HTTP port (default: `80`) |
| `HTTPS_PORT` | External HTTPS port (default: `443`) |

**ACME CA server URLs:**
- **Staging** (for testing): `https://acme-staging-v02.api.letsencrypt.org/directory`
- **Production** (for real certs): `https://acme-v02.api.letsencrypt.org/directory`

### Legacy Environment Variables

These are supported for backward compatibility. After migrating to the database with `python3 migrate_env.py`, they can be removed.

| Variable | Description |
|----------|-------------|
| `USERNAME` | DynDNS username |
| `PASSWORD` | Bcrypt-hashed password |
| `DOMAINS` | Comma-separated list of allowed domains |
| `AWS_ACCESS_KEY_ID` | AWS access key for Route53 |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key |
| `NSUPDATE_KEY` | TSIG key name |
| `NSUPDATE_ALGO` | TSIG algorithm (e.g. `hmac-sha512`) |
| `NSUPDATE_SECRET` | TSIG shared secret (base64) |
| `NSUPDATE_NAMESERVER` | IP of the authoritative nameserver |

## Managing Users and Domains

All user and domain management is done through the web UI at `/admin/`.

**As admin:**
1. Create users at `/admin/users/new`
2. Assign domains to users at `/admin/users/<id>/domains`
3. Configure backend credentials per domain at the domain config page

Each user can have multiple domains, each with its own backend type (AWS or nsupdate) and credentials. Credentials are Fernet-encrypted at rest in the database.

## Generating Passwords

Passwords are stored as bcrypt hashes. Use the included utility to generate one:

```bash
# Generate a random password and its hash
python3 getpwd.py

# Hash a specific password
python3 getpwd.py mypassword
```

If running via Docker without a local Python environment:

```bash
docker run --rm ghcr.io/brendanbank/dyndns-route53:latest python3 /app/getpwd.py
```

## Testing

### Automated tests

```bash
# Run the pytest suite (48 tests)
python -m pytest tests/ -v

# Lint check
ruff check .
```

### Manual testing

**curl with HTTP Basic Auth:**

```bash
curl -u username:password \
  "https://dyndns.example.com/nic/update?hostname=home.dyn.example.com&myip=203.0.113.1"
```

**Using the nsupdate backend:**

```bash
curl -u username:password \
  "https://dyndns.example.com/nic/update?hostname=home.dyn.example.com&myip=203.0.113.1&updatetype=nsupdate"
```

**Testing against a local Traefik instance:**

When testing locally, Traefik routes by `Host` header, so you must pass it explicitly. Use `-k` to accept the self-signed staging certificate:

```bash
curl -k -u username:password \
  -H "Host: ${TRAEFIK_HOSTNAME}" \
  "https://localhost:${HTTPS_PORT}/nic/update?hostname=home.dyn.example.com&myip=203.0.113.1"
```

### Deployment smoke test

```bash
# Against production (HTTPS)
./tests/smoke_test.sh --host dyndns.example.com --user admin --pass secret

# Against local Flask dev server (HTTP)
./tests/smoke_test.sh --http --host localhost:8080 --user admin --pass secret

# Against local Docker with Traefik (HTTPS, resolve hostname to localhost)
./tests/smoke_test.sh --host dyndns.example.com:9443 --resolve 127.0.0.1 --user admin --pass secret
```

**Expected responses:**
- `good <ip>` — record created or updated
- `nochg <ip>` — IP unchanged, no update needed
- `nohost <ip>` — hostname not in user's assigned domains
- `badauth` — invalid credentials
- `notfqdn` — invalid hostname format
- `911` — server error
