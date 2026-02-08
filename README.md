# dyndns-route53

A Dynamic DNS web service that implements the [DynDNS v2 protocol](https://help.dyn.com/remote-access-api/perform-update/) over HTTP. It accepts standard `/nic/update` requests and updates DNS records through pluggable backends:

- **AWS Route53** — updates hosted zones via the AWS API (boto3)
- **BIND nsupdate** — updates DNS via TSIG-authenticated dynamic updates (dnspython)

Originally built because the OPNsense DynDNS plugin did not support AWS Route53. Works with any DynDNS v2 compatible client.

## Quick Start

### Using the pre-built Docker image

```bash
docker pull ghcr.io/brendanbank/dyndns-route53:latest
cp .env.example .env   # create .env and fill in your credentials
docker compose up -d
```

### Building from source

```bash
cp .env.example .env   # create .env and fill in your credentials
docker compose up --build
```

See [INSTALLING.md](INSTALLING.md) for full installation options (Docker, manual setup) and configuration reference.

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

## How It Works

1. Client sends an update request to `/nic/update`
2. The service authenticates via HTTP Basic Auth against the bcrypt-hashed password
3. Hostnames are validated and mapped to their respective DNS zones
4. Before updating, the service queries the authoritative nameserver to check if the IP has actually changed
5. If changed, the selected backend (Route53 or nsupdate) creates/updates the DNS record

Both IPv4 (A records) and IPv6 (AAAA records) are supported and auto-detected from the provided IP address.

## License

BSD 3-Clause License. See [LICENSE](LICENSE).
