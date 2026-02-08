# Installation & Configuration

## Docker Installation (Pre-built Image)

The easiest way to run dyndns-route53 is with the pre-built Docker image and the example compose file.

1. Download [`compose.example.yaml`](compose.example.yaml) and [`.env.example`](.env.example)
2. Copy and configure:
   ```bash
   cp compose.example.yaml compose.yaml
   cp .env.example .env
   # Edit .env with your credentials and domain settings
   ```
3. Generate a bcrypt password hash (see [Generating Passwords](#generating-passwords))
4. Start the service:
   ```bash
   docker compose up -d
   ```

Traefik handles TLS termination via Let's Encrypt. HTTP (port 80) redirects to HTTPS (port 443) automatically.

## Docker Installation (Local Build)

To build the image locally from source:

```bash
git clone git@github.com:brendanbank/dyndns-route53.git
cd dyndns-route53
cp .env.example .env   # edit with your credentials
docker compose up --build
```

## Manual Installation

```bash
git clone git@github.com:brendanbank/dyndns-route53.git
cd dyndns-route53
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Run the development server:

```bash
venv/bin/python wsgi.py
```

The Flask dev server listens on `0.0.0.0:8080`. For production, use Docker Compose with Traefik.

## Configuration

All configuration is done through environment variables in a `.env` file. See [`.env.example`](.env.example) for a template.

### General (required)

| Variable | Description |
|----------|-------------|
| `USERNAME` | Username for DynDNS v2 HTTP Basic Authentication |
| `PASSWORD` | Bcrypt-hashed password (generate with `python3 getpwd.py`) |
| `DOMAINS` | Comma-separated list of domains allowed for updates (e.g. `dyn.example.com,example.org`) |
| `DEBUG` | Set to `DEBUG` for verbose logging |

### AWS Route53 Backend

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key with IAM permissions for Route53 |
| `AWS_SECRET_ACCESS_KEY` | Secret key linked to the access key |

The AWS backend automatically discovers hosted zones from your Route53 account. Only zones matching `DOMAINS` will be used.

### nsupdate Backend

| Variable | Description |
|----------|-------------|
| `NSUPDATE_KEY` | TSIG key name |
| `NSUPDATE_ALGO` | TSIG algorithm (e.g. `hmac-sha512`) |
| `NSUPDATE_SECRET` | TSIG shared secret (base64) |
| `NSUPDATE_NAMESERVER` | IP address of the authoritative nameserver |

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

Put the bcrypt hash in your `.env` as `PASSWORD`.
