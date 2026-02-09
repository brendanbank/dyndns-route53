# DynDNS v2 Protocol Reference

There is no formal RFC or official specification for the DynDNS v2 protocol. The protocol originated as the Remote Access Update API of Dyn.com (formerly DynDNS.org) and became a de facto standard adopted by many dynamic DNS providers and client implementations. This document reconstructs the protocol from Dyn's published API documentation and documents the extensions that various vendors have added.

## Table of Contents

- [1. Core Protocol (Dyn.com Remote Access API)](#1-core-protocol-dyncom-remote-access-api)
  - [1.1 Endpoint](#11-endpoint)
  - [1.2 Authentication](#12-authentication)
  - [1.3 HTTP Method](#13-http-method)
  - [1.4 User-Agent Requirements](#14-user-agent-requirements)
  - [1.5 Query Parameters](#15-query-parameters)
  - [1.6 Return Codes](#16-return-codes)
  - [1.7 IP Detection](#17-ip-detection)
  - [1.8 Rate Limiting and Abuse Policies](#18-rate-limiting-and-abuse-policies)
- [2. Vendor Implementations](#2-vendor-implementations)
  - [2.1 No-IP](#21-no-ip)
  - [2.2 easyDNS](#22-easydns)
  - [2.3 Dynu](#23-dynu)
  - [2.4 DNS-O-Matic](#24-dns-o-matic)
  - [2.5 ChangeIP](#25-changeip)
  - [2.6 deSEC.io](#26-desecio)
  - [2.7 nsupdate.info](#27-nsupdateinfo)
  - [2.8 DuckDNS](#28-duckdns)
  - [2.9 FreeDNS (afraid.org)](#29-freedns-afraidorg)
  - [2.10 Google Domains (now Squarespace)](#210-google-domains-now-squarespace)
  - [2.11 Cloudflare](#211-cloudflare)
- [3. Common Clients](#3-common-clients)
  - [3.1 ddclient](#31-ddclient)
  - [3.2 inadyn](#32-inadyn)
  - [3.3 Fritz!Box (AVM)](#33-fritzbox-avm)
  - [3.4 OPNsense](#34-opnsense)
- [4. Comparison Tables](#4-comparison-tables)
  - [4.1 Authentication Methods](#41-authentication-methods)
  - [4.2 IPv6 Support](#42-ipv6-support)
  - [4.3 Offline / Record Deletion](#43-offline--record-deletion)
  - [4.4 Return Codes](#44-return-codes)
- [5. Sources](#5-sources)

---

## 1. Core Protocol (Dyn.com Remote Access API)

### 1.1 Endpoint

| Property | Value |
|----------|-------|
| Hostname | `members.dyndns.org` |
| Path | `/nic/update` (de facto standard, used by all clients and providers). Dyn.com also offered `/v3/update` |
| Ports | HTTP: 80, 8245; HTTPS: 443 (recommended) |

Example request:

```
GET /nic/update?hostname=example.dyndns.org&myip=203.0.113.1 HTTP/1.1
Host: members.dyndns.org
Authorization: Basic dXNlcjpwYXNz
User-Agent: MyClient/1.0 info@example.com
```

### 1.2 Authentication

HTTP Basic Authentication. The username and password are sent as a Base64-encoded `Authorization` header. Some providers also accept credentials in the URL (`https://user:pass@host/nic/update`) or as query parameters (`?username=...&password=...`), but these are discouraged for security reasons.

### 1.3 HTTP Method

**GET** is the standard method. POST is accepted by some providers but may be discontinued without notice. Other HTTP methods are not supported and trigger a `badagent` return code.

### 1.4 User-Agent Requirements

Clients must send a descriptive `User-Agent` header containing the client name and version. Dyn.com required the format `Company - Device - Version` (e.g., `Acme Router 3000 - 2.1`). Missing or generic User-Agent strings trigger a `badagent` return code and may result in the client being blocked.

### 1.5 Query Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `hostname` | Yes | Comma-separated list of FQDNs to update (max 20) |
| `myip` | No | IPv4 (or IPv6) address to set. Auto-detected from the request source IP if omitted |
| `wildcard` | No | `ON`, `NOCHG`, or omit. **Deprecated** — currently ignored by Dyn |
| `mx` | No | Mail exchanger hostname or `NOCHG`. **Deprecated** — currently ignored by Dyn |
| `backmx` | No | `YES`, `NOCHG`, or omit. **Deprecated** — currently ignored by Dyn |
| `offline` | No | `YES` activates offline redirect for the hostname. `NOCHG` keeps current state. Requires a credited account; not available for static DNS hosts |
| `system` | No | Legacy parameter. Accepted without error but not required |
| `url` | No | Reserved for future use |

Unrecognized parameter names may trigger an `abuse` return code.

### 1.6 Return Codes

The response body is plain text. For multi-hostname requests, one return code appears per line, in the same order as the hostnames in the request.

| Code | Example | Meaning | Client Action |
|------|---------|---------|---------------|
| `good` | `good 203.0.113.1` | Update successful | Continue normal operation |
| `nochg` | `nochg 203.0.113.1` | IP has not changed | Stop sending updates until IP changes. Repeated `nochg` is considered abuse |
| `badauth` | `badauth` | Invalid username or password | Stop updating. Do not retry without user intervention |
| `notfqdn` | `notfqdn` | Hostname is not a valid FQDN | Stop updating. Fix hostname |
| `nohost` | `nohost` | Hostname does not exist in this account | Stop updating. Fix hostname |
| `numhost` | `numhost` | Too many hostnames (>20) or round-robin update attempted | Reduce hostname count |
| `abuse` | `abuse` | Hostname blocked for update abuse | Stop updating. Contact provider |
| `badagent` | `badagent` | Bad User-Agent or unsupported HTTP method | Fix client User-Agent header |
| `!donator` | `!donator` | Premium feature requested by non-credited user | Remove premium options from request |
| `dnserr` | `dnserr` | DNS error on provider side | Stop updating. Wait 30 minutes minimum |
| `911` | `911` | Provider-side outage or maintenance | Stop updating. Wait 30 minutes minimum |

### 1.7 IP Detection

Dyn provided an IP detection endpoint for clients to determine their public IP before deciding whether to send an update:

| Property | Value |
|----------|-------|
| URL | `http://checkip.dyndns.org/` |
| Response | `<html><head><title>Current IP Check</title></head><body>Current IP Address: 203.0.113.1</body></html>` |

The endpoint returns the client's source IP as seen by the server. If the client sends `X-Forwarded-For` or `Client-IP` headers, those values are returned instead.

Clients should not query this endpoint more than once every 10 minutes.

### 1.8 Rate Limiting and Abuse Policies

- Only send an update when the IP address has actually changed.
- Do not send updates more frequently than once every 10 minutes.
- If the response is `nochg`, the client must not retry until the IP changes. Repeated `nochg` responses lead to hostname blocking (`abuse`).
- After receiving `badauth`, `notfqdn`, `nohost`, `abuse`, or `badagent`, the client must stop all updates and require user intervention before resuming.
- After `dnserr` or `911`, the client must wait at least 30 minutes before retrying.
- Hard-coded IP addresses for the update server are not acceptable; always resolve the hostname.

---

## 2. Vendor Implementations

### 2.1 No-IP

**Endpoint:** `https://dynupdate.no-ip.com/nic/update`
**Protocol compliance:** Full DynDNS v2, with extensions

No-IP follows the core protocol closely. Key differences:

- **Authentication:** HTTP Basic Auth. The username is the account email address (max 50 characters).
- **IPv6:** Supported. The `myip` parameter accepts IPv4, IPv6, or both comma-separated. A dedicated `myipv6` parameter is also available.
- **Offline:** `offline=YES/NO` (Enhanced accounts only).
- **Return codes:** Standard DynDNS v2.
- **User-Agent:** Strictly enforced. Non-certified clients risk rate-limiting or blocking.

| Parameter | Description |
|-----------|-------------|
| `hostname` | Comma-separated hostnames and groups |
| `myip` | IPv4 or IPv6 (auto-detected if omitted) |
| `myipv6` | Explicit IPv6 address |
| `offline` | `YES`/`NO` (Enhanced only) |

### 2.2 easyDNS

**Endpoint:** `https://api.cp.easydns.com/dyn/generic.php`
**Protocol compliance:** Partial — different return codes, `0.0.0.0` extension

easyDNS uses its own return codes and adds a vendor-specific extension for offline mode:

- **Authentication:** HTTP Basic Auth with dynamic tokens (not passwords).
- **IPv6:** Supported. IPv6 addresses must be URL-encoded (`:` as `%3A`).
- **Offline:** Sending `myip=0.0.0.0` sets the record to an offline state, resolving to `offline.easydns.com`. This is unique to easyDNS.
- **Rate limiting:** Minimum 10 minutes between updates (`TOOSOON` error).

| Parameter | Description |
|-----------|-------------|
| `hostname` | FQDN to update |
| `TLD` | Root domain (optional for second-level domains) |
| `myip` | IP address; `0.0.0.0` = offline |
| `MX` | Mail exchange (default preference 5) |
| `backmx` | `YES`/`NO` for backup mail spool |
| `wildcard` | `ON`/`OFF`/`YES` |

| Return Code | Meaning |
|-------------|---------|
| `NOERROR` / `OK` | Success |
| `NOACCESS` / `NO_AUTH` | Authentication failure |
| `NOSERVICE` | Dynamic DNS not enabled |
| `ILLEGAL INPUT` | Invalid request |
| `TOOSOON` | Less than 10 minutes since last update |

### 2.3 Dynu

**Endpoint:** `https://api.dynu.com/nic/update`
**Protocol compliance:** Full DynDNS v2, with extensions

- **Authentication:** HTTP Basic Auth. Passwords can be sent as plaintext, MD5, or SHA-256 hashes.
- **IPv6:** Supported via `myipv6` parameter and dedicated endpoints (`api-ipv4.dynu.com`, `api-ipv6.dynu.com`).
- **Offline:** `offline=yes` supported.
- **Special IP values:** `myip=10.0.0.0` is replaced with the request source IP. `myip=no` or `myipv6=no` blocks that address type from being updated.
- **Groups:** The `group` parameter updates a collection of hostnames at once.
- **Return codes:** Standard DynDNS v2 plus `servererror` and `unknown`.

### 2.4 DNS-O-Matic

**Endpoint:** `https://updates.dnsomatic.com/nic/update`
**Protocol compliance:** Full DynDNS v2

DNS-O-Matic is an aggregator that distributes updates to multiple DNS providers. It mirrors the Dyn.com API exactly, including all parameters and return codes. Use `hostname=all.dnsomatic.com` to update all configured services.

IP detection endpoint: `http://myip.dnsomatic.com/` (returns plain text IP).

### 2.5 ChangeIP

**Endpoint:** `https://nic.changeip.com/nic/update`
**Protocol compliance:** Full DynDNS v2, with extensions

- **Authentication:** HTTP Basic Auth or query parameters (`u=`, `p=`).
- **Offline:** `offline=1` updates with a configured offline address (IP, CNAME, or URL).
- **Sets:** The `set=` parameter (1 or 2) updates a batch of hostnames with a single request.
- **Return codes:** Standard DynDNS v2.

### 2.6 deSEC.io

**Endpoint:** `https://update.dedyn.io/`
**Protocol compliance:** Extended DynDNS v2

deSEC offers significant extensions beyond the core protocol:

- **Authentication:** HTTP Basic Auth or token-based (`Authorization: Token <secret>`).
- **IPv6:** Full support with dedicated parameters (`myipv4`, `myipv6`, `ipv6`) and an IPv6-specific endpoint (`https://update6.dedyn.io/`).
- **Prefix notation:** IPv6 addresses can include prefix length (e.g., `myipv6=2001:db8::/48`).
- **Preserve:** The special value `preserve` retains existing records when updating only one address family.
- **Delete:** An empty value deletes the record. A dedicated `/nic/delete` endpoint also exists.
- **Return codes:** Uses HTTP status codes (200, 400, 401, 404) with `good` in the body on success.

| Parameter | Description |
|-----------|-------------|
| `hostname` | FQDN(s) to update (comma-separated) |
| `myip` | IPv4 or IPv6 |
| `myipv4` | Explicit IPv4 |
| `myipv6` | Explicit IPv6 (supports prefix notation) |

### 2.7 nsupdate.info

**Endpoint:** DynDNS v2-compatible frontend
**Protocol compliance:** Full DynDNS v2

nsupdate.info bridges the DynDNS v2 protocol to RFC 2136 DNS UPDATE on the backend. It adds a `/nic/delete` endpoint (not part of the original protocol) that removes A/AAAA records using the same authentication and parameter format.

### 2.8 DuckDNS

**Endpoint:** `https://www.duckdns.org/update`
**Protocol compliance:** Not DynDNS v2 compatible

DuckDNS uses a completely different protocol:

- **Authentication:** Token-based only (no Basic Auth).
- **IPv6:** Supported via dedicated `ipv6` parameter.
- **Clear records:** `clear=true` removes all DNS records.
- **Return codes:** `OK` or `KO` (with optional verbose mode).

| Parameter | Description |
|-----------|-------------|
| `domains` | Subdomain(s) to update |
| `token` | Authentication token |
| `ip` | IPv4 or IPv6 (auto-detected if omitted) |
| `ipv6` | Explicit IPv6 |
| `verbose` | Return detailed response |
| `clear` | Clear all records |
| `txt` | TXT record value |

### 2.9 FreeDNS (afraid.org)

**Endpoint:** `https://freedns.afraid.org/dynamic/update.php?<token>`
**Protocol compliance:** Not DynDNS v2 compatible

FreeDNS uses a token-in-URL scheme. Each subdomain gets a unique random token. An HTTP GET to the URL with the token updates the record to the client's source IP. No username, password, or hostname parameters are needed.

V2 endpoint: `https://sync.afraid.org/u/<token>/`

### 2.10 Google Domains (now Squarespace)

**Endpoint:** `https://domains.google.com/nic/update`
**Protocol compliance:** Full DynDNS v2

Google Domains implemented the standard DynDNS v2 protocol with HTTP Basic Auth using generated credentials. The service was migrated to Squarespace in 2024.

### 2.11 Cloudflare

**Protocol compliance:** Not DynDNS v2 compatible

Cloudflare does not offer a DynDNS-compatible endpoint. DNS records must be managed through the Cloudflare REST API v4 (`https://api.cloudflare.com/client/v4/`), using API tokens for authentication. Clients like ddclient and inadyn include Cloudflare-specific protocol handlers.

---

## 3. Common Clients

### 3.1 ddclient

Perl-based client with broad protocol support. Supports `dyndns2` as well as many vendor-specific protocols. Configuration uses `protocol=dyndns2` with `server`, `login`, `password`, and hostname settings.

Note: ddclient's config uses `backupmx` while the protocol parameter is `backmx`.

### 3.2 inadyn

Lightweight C-based client with HTTPS support. Supports DynDNS v2, Cloudflare, and many other providers. IPv6 support with `allow-ipv6 = true`. Includes a generic/custom DDNS plugin for unsupported providers.

### 3.3 Fritz!Box (AVM)

Fritz!Box routers support custom DynDNS URLs with placeholder substitution:

| Placeholder | Value |
|-------------|-------|
| `<ipaddr>` | IPv4 address |
| `<ip6addr>` | IPv6 address |
| `<username>` | Username |
| `<pass>` / `<passwd>` | Password |
| `<domain>` | Domain name |
| `<ip6lanprefix>` | IPv6 LAN prefix |

Limitations: Username, Password, and Domain fields cannot be empty. If a provider uses token-based auth, dummy values must be entered in unused fields.

### 3.4 OPNsense

Python-based DynDNS client with a plugin architecture. Supports DynDNS v2, Route53, and custom HTTP services. Uses a factory pattern for auto-discovery of backend handlers. Configurable IP detection and interface binding.

---

## 4. Comparison Tables

### 4.1 Authentication Methods

| Provider | Basic Auth | Token | API Key | URL Credentials | Query Params |
|----------|:----------:|:-----:|:-------:|:---------------:|:------------:|
| Dyn.com (original) | Yes | - | - | Yes | Yes |
| No-IP | Yes | - | - | - | - |
| easyDNS | Yes | - | - | Yes | - |
| Dynu | Yes | - | - | - | Yes |
| DNS-O-Matic | Yes | - | - | Yes | - |
| ChangeIP | Yes | - | - | - | Yes |
| deSEC.io | Yes | Yes | - | - | Yes |
| nsupdate.info | Yes | - | - | - | - |
| Google Domains | Yes | - | - | - | - |
| DuckDNS | - | Yes | - | - | - |
| FreeDNS | - | Yes | - | - | - |
| Cloudflare | - | - | Yes | - | - |

### 4.2 IPv6 Support

| Provider | IPv6 | Parameter | Notes |
|----------|:----:|-----------|-------|
| Dyn.com (original) | Yes | `myip` | Comma-separated dual-stack |
| No-IP | Yes | `myip`, `myipv6` | Dedicated IPv6 parameter |
| easyDNS | Yes | `myip` | URL-encode colons (`%3A`) |
| Dynu | Yes | `myip`, `myipv6` | Dedicated endpoints per address family |
| DNS-O-Matic | Limited | `myip` | Depends on downstream provider |
| deSEC.io | Yes | `myipv4`, `myipv6`, `ipv6` | Prefix notation, dedicated endpoint |
| DuckDNS | Yes | `ip`, `ipv6` | Dedicated parameter |
| Google Domains | Yes | `myip` | |

### 4.3 Offline / Record Deletion

The original DynDNS v2 protocol has no mechanism to delete a DNS record. The `offline` parameter sets a redirect, not a deletion. Various vendors have added their own extensions:

| Provider | Mechanism | Effect |
|----------|-----------|--------|
| Dyn.com (original) | `offline=YES` | Redirects to an offline page (credited accounts only) |
| No-IP | `offline=YES` | Offline mode (Enhanced accounts only) |
| easyDNS | `myip=0.0.0.0` | Resolves to `offline.easydns.com` |
| Dynu | `offline=yes` | Offline message |
| ChangeIP | `offline=1` | Updates with configured offline address |
| DNS-O-Matic | `offline=YES` | Passed through to downstream provider |
| deSEC.io | Empty value or `/nic/delete` | Deletes A/AAAA records |
| nsupdate.info | `/nic/delete` | Deletes A/AAAA records |
| DuckDNS | `clear=true` | Clears all records |

### 4.4 Return Codes

| Code | Dyn | No-IP | easyDNS | Dynu | deSEC | DuckDNS |
|------|:---:|:-----:|:-------:|:----:|:-----:|:-------:|
| `good <ip>` | Yes | Yes | - | Yes | Yes | - |
| `nochg <ip>` | Yes | Yes | - | Yes | - | - |
| `badauth` | Yes | Yes | - | Yes | HTTP 401 | - |
| `notfqdn` | Yes | Yes | - | Yes | - | - |
| `nohost` | Yes | Yes | - | Yes | HTTP 404 | - |
| `numhost` | Yes | Yes | - | Yes | - | - |
| `abuse` | Yes | Yes | - | Yes | - | - |
| `badagent` | Yes | Yes | - | - | - | - |
| `dnserr` | Yes | Yes | - | Yes | - | - |
| `911` | Yes | Yes | - | Yes | - | - |
| `!donator` | Yes | Yes | - | Yes | - | - |
| `OK` / `NOERROR` | - | - | Yes | - | - | Yes |
| `KO` | - | - | - | - | - | Yes |
| `TOOSOON` | - | - | Yes | - | - | - |
| `NOACCESS` | - | - | Yes | - | - | - |

---

## 5. Sources

### Dyn.com (Original Protocol)

- [Remote Access API](http://help.dyn.com/remote-access-api.html) — API overview
- [Perform Update](http://help.dyn.com/perform-update.html) — Update endpoint specification
- [Return Codes](http://help.dyn.com/return-codes.html) — Response code reference
- [CheckIP Tool](http://help.dyn.com/checkip-tool.html) — IP detection endpoint
- [Policies](http://help.dyn.com/remote-access-api/policies/) — Rate limiting and abuse policies

### Vendor Documentation

- [No-IP Integration](https://www.noip.com/integrate/request) — No-IP API documentation
- [easyDNS Dynamic DNS](https://kb.easydns.com/knowledge/dynamic-dns/) — easyDNS protocol
- [Dynu IP Update Protocol](https://www.dynu.com/DynamicDNS/IP-Update-Protocol) — Dynu API documentation
- [DNS-O-Matic API](https://dnsomatic.com/docs/api) — DNS-O-Matic specification
- [ChangeIP DDNS API](https://www.changeip.com/accounts/index.php?rp=/knowledgebase/34/DDNS-API-Information.html) — ChangeIP specification
- [deSEC DynDNS Update API](https://desec.readthedocs.io/en/latest/dyndns/update-api.html) — deSEC documentation
- [DuckDNS Specification](https://www.duckdns.org/spec.jsp) — DuckDNS API
- [Google Domains DDNS](https://support.google.com/domains/answer/6147083) — Google Domains (now Squarespace)

### Client Documentation

- [ddclient Protocols](https://github.com/ddclient/ddclient/wiki/protocols) — ddclient protocol support
- [inadyn GitHub](https://github.com/troglobit/inadyn) — inadyn client
- [OPNsense Dynamic DNS](https://docs.opnsense.org/manual/dynamic_dns.html) — OPNsense implementation
