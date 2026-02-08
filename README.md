# dyndns-route53

A Dynamic DNS web service that implements the [DynDNS v2 protocol](https://help.dyn.com/remote-access-api/perform-update/) over HTTP. It accepts standard `/nic/update` requests and updates DNS records through pluggable backends:

- **AWS Route53** — updates hosted zones via the AWS API (boto3)
- **BIND nsupdate** — updates DNS via TSIG-authenticated dynamic updates (dnspython)

Originally built because the OPNsense DynDNS plugin did not support AWS Route53. Works with any DynDNS v2 compatible client.

## Quick Start with Docker

### Using the pre-built image

```bash
docker pull ghcr.io/brendanbank/dyndns-route53:latest
cp .env.example .env   # create .env and fill in your credentials
docker compose up -d
```

### Building locally

```bash
cp .env.example .env   # create .env and fill in your credentials
docker compose up --build
```

Traefik handles TLS termination via Let's Encrypt. The service will be available on HTTPS (port 443), with HTTP (port 80) redirecting automatically.

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

For production, use Docker Compose with Traefik (see Quick Start above).

## Configuration

Create a `.env` file in the project root. All configuration is done through environment variables.

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

### Traefik Reverse Proxy

| Variable | Description |
|----------|-------------|
| `TRAEFIK_HOSTNAME` | Domain name for the TLS certificate (e.g. `dyndns.example.com`) |
| `LETSENCRYPT_EMAIL` | Email address for Let's Encrypt registration |
| `LETSENCRYPT_CASERVER` | ACME CA server URL (use staging for testing, production for real certs) |
| `HTTP_PORT` | External HTTP port (default: `80`) |
| `HTTPS_PORT` | External HTTPS port (default: `443`) |

**ACME CA server URLs:**
- Staging: `https://acme-staging-v02.api.letsencrypt.org/directory`
- Production: `https://acme-v02.api.letsencrypt.org/directory`

### nsupdate Backend

| Variable | Description |
|----------|-------------|
| `NSUPDATE_KEY` | TSIG key name |
| `NSUPDATE_ALGO` | TSIG algorithm (e.g. `hmac-sha512`) |
| `NSUPDATE_SECRET` | TSIG shared secret (base64) |
| `NSUPDATE_NAMESERVER` | IP address of the authoritative nameserver |

## Usage

### API Endpoint

```
GET /nic/update?hostname=<hostname>&myip=<ip>&updatetype=<backend>
```

**Authentication:** HTTP Basic Auth (preferred) or `username`/`password` query parameters.

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `hostname` | Yes | FQDN to update (comma-separated for multiple) |
| `myip` | No | IP address to set (defaults to client IP via `X-Forwarded-For`) |
| `updatetype` | No | Backend to use: `aws` (default) or `nsupdate` |

**Example with curl:**

```bash
curl -u username:password "https://dyndns.example.com/nic/update?hostname=home.dyn.example.com&myip=203.0.113.1"
```

**Example with wget:**

```bash
wget -O - --auth-no-challenge --user=username --password=password \
  "https://dyndns.example.com/nic/update?hostname=home.dyn.example.com&myip=203.0.113.1"
```

### Generating Passwords

Passwords are stored as bcrypt hashes. Use the included utility to generate one:

```bash
# Generate a random password and its hash
python3 getpwd.py

# Hash a specific password
python3 getpwd.py mypassword
```

Put the bcrypt hash in your `.env` as `PASSWORD`.

### OPNsense Configuration

In OPNsense, configure a DynDNS entry with:
- **Service:** Custom
- **Protocol:** DynDNS v2
- **Server:** Your server's hostname/IP and port
- **Username/Password:** As configured in `.env`
- **Hostname:** The FQDN to update

## How It Works

1. Client sends an update request to `/nic/update`
2. The service authenticates via HTTP Basic Auth against the bcrypt-hashed password
3. Hostnames are validated and mapped to their respective DNS zones
4. Before updating, the service queries the authoritative nameserver to check if the IP has actually changed
5. If changed, the selected backend (Route53 or nsupdate) creates/updates the DNS record

Both IPv4 (A records) and IPv6 (AAAA records) are supported and auto-detected from the provided IP address.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
