# dyndns-route53

A Dynamic DNS web service that implements the [DynDNS v2 protocol](https://help.dyn.com/remote-access-api/perform-update/) over HTTP. It accepts standard `/nic/update` and `/nic/delete` requests and updates DNS records through pluggable backends:

- **AWS Route53** — updates hosted zones via the AWS API (boto3)
- **BIND nsupdate** — updates DNS via TSIG-authenticated dynamic updates (dnspython)

Supports multi-user operation with global admin-managed domains, per-user hostnames, per-domain backends with Fernet-encrypted credentials in SQLite, and a Bootstrap 5 web UI for administration with mandatory TOTP two-factor authentication.

Originally built because the OPNsense DynDNS plugin did not support AWS Route53. Works with any DynDNS v2 compatible client.

## Quick Start

### Using the pre-built Docker image

```bash
docker pull ghcr.io/brendanbank/dyndns-route53:latest
cp compose.example.yaml compose.yaml
cp .env.example .env   # edit with your SECRET_KEY, FERNET_KEY, ADMIN_PASSWORD, and Traefik settings
docker compose up -d
```

The database and admin user are created automatically on first boot. `ADMIN_PASSWORD` accepts plaintext (hashed automatically) or a pre-computed bcrypt hash.

### Building from source

```bash
git clone git@github.com:brendanbank/dyndns-route53.git
cd dyndns-route53
cp .env.example .env   # edit with your credentials
docker compose up --build
```

See [INSTALLING.md](INSTALLING.md) for full installation options (Docker, manual setup) and configuration reference.

## Web UI

The admin interface is at `/admin/login`. After logging in with your password, you'll be prompted to set up TOTP two-factor authentication on first login.

**Admin features:** user management, global domain management, per-domain backend configuration with encrypted credentials, per-user hostname management, event log viewer.

**User self-service:** register/remove hostnames under available domains, browse own event history, change password, reset 2FA.

## API Endpoints

### Update DNS record

```
GET /nic/update?hostname=<hostname>&myip=<ip>
```

### Delete DNS record

```
GET /nic/delete?hostname=<hostname>&myip=<ip>
```

**Authentication:** HTTP Basic Auth (preferred) or `username`/`password` query parameters. No TOTP required for API access.

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `hostname` | Yes | FQDN to update/delete (comma-separated for multiple) |
| `myip` | No | IP address (update: defaults to client IP; delete: if omitted, removes both A and AAAA) |

**Examples:**

```bash
# Update a record
curl -u username:password "https://dyndns.example.com/nic/update?hostname=home.dyn.example.com&myip=203.0.113.1"

# Delete a record
curl -u username:password "https://dyndns.example.com/nic/delete?hostname=home.dyn.example.com"
```

**Responses:** `good <ip>`, `nochg <ip>`, `badauth`, `notfqdn`, `nohost`, `911`

## How It Works

1. Client sends a request to `/nic/update` or `/nic/delete`
2. The service authenticates via HTTP Basic Auth against the user's bcrypt-hashed password
3. Hostnames are validated and matched against the user's registered hostnames
4. Before updating, the service queries the authoritative nameserver to check if the IP has actually changed
5. If changed, all backends configured for the hostname's domain create/update/delete the DNS record
6. Each operation is logged to the events database

Both IPv4 (A records) and IPv6 (AAAA records) are supported and auto-detected from the provided IP address.

## Testing

```bash
# Run the test suite
python -m pytest tests/ -v

# Lint
ruff check .

# Deployment smoke test (HTTPS, production)
./tests/smoke_test.sh --host dyndns.example.com --user admin --pass secret

# Deployment smoke test (HTTP, local dev)
./tests/smoke_test.sh --http --host localhost:8080 --user admin --pass secret

# Deployment smoke test (HTTPS, local Docker with Traefik)
./tests/smoke_test.sh --host dyndns.example.com:9443 --resolve 127.0.0.1 --user admin --pass secret
```

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
