#!/usr/bin/env bash
#
# Deployment smoke test for dyndns-route53
#
# Usage (production):
#   ./tests/smoke_test.sh --host dyndns.example.com --user admin --pass secret
#
# Usage (local dev, Flask):
#   ./tests/smoke_test.sh --http --host localhost:8080 --user admin --pass secret
#
# Usage (local Docker with Traefik):
#   ./tests/smoke_test.sh --host dyndns.example.com:9443 --resolve localhost --user admin --pass secret
#
# Or via environment variables:
#   HOST=dyndns.example.com USERNAME=admin PASSWORD=secret ./tests/smoke_test.sh
#

# --- Parse args ---
SCHEME="https"
RESOLVE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)    HOST="$2"; shift 2 ;;
        --user)    USERNAME="$2"; shift 2 ;;
        --pass)    PASSWORD="$2"; shift 2 ;;
        --http)    SCHEME="http"; shift ;;
        --resolve) RESOLVE="$2"; shift 2 ;;
        *)         echo "Unknown option: $1"; exit 1 ;;
    esac
done

HOST="${HOST:?HOST is required (--host or \$HOST)}"
USERNAME="${USERNAME:?USERNAME is required (--user or \$USERNAME)}"
PASSWORD="${PASSWORD:?PASSWORD is required (--pass or \$PASSWORD)}"

BASE_URL="${SCHEME}://${HOST}"
PASS_COUNT=0
FAIL_COUNT=0

# Build curl resolve flag: --resolve hostname:port:ip
CURL_OPTS=(-s -k)
if [ -n "$RESOLVE" ]; then
    # Extract hostname and port from HOST
    HOSTNAME="${HOST%%:*}"
    PORT="${HOST##*:}"
    if [ "$PORT" = "$HOSTNAME" ]; then
        # No port in HOST — use default for scheme
        if [ "$SCHEME" = "https" ]; then PORT=443; else PORT=80; fi
    fi
    CURL_OPTS+=(--resolve "${HOSTNAME}:${PORT}:${RESOLVE}")
fi

pass() {
    echo "  PASS  $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo "  FAIL  $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "Smoke testing ${BASE_URL}${RESOLVE:+ (resolve via ${RESOLVE})} ..."
echo

# 1. Login page returns 200 with a form
body=$(curl "${CURL_OPTS[@]}" "${BASE_URL}/admin/login" -w '\n%{http_code}')
code=$(echo "$body" | tail -n1)
if [ "$code" = "200" ] && echo "$body" | grep -q '<form'; then
    pass "Login page returns 200 with form"
else
    fail "Login page returns 200 with form (got ${code})"
fi

# 2. Bad login does not 500
code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w '%{http_code}' \
    -X POST -d "username=bogus&password=bogus" "${BASE_URL}/admin/login")
if [ "$code" != "500" ]; then
    pass "Bad login does not 500 (got ${code})"
else
    fail "Bad login does not 500 (got ${code})"
fi

# 3. /nic/update with bad auth returns badauth
body=$(curl "${CURL_OPTS[@]}" -u "baduser:badpass" "${BASE_URL}/nic/update?hostname=test.example.com&myip=1.2.3.4")
if echo "$body" | grep -q 'badauth'; then
    pass "/nic/update bad auth -> badauth"
else
    fail "/nic/update bad auth -> badauth (got: ${body})"
fi

# 4. /nic/update with no auth returns badauth
body=$(curl "${CURL_OPTS[@]}" "${BASE_URL}/nic/update?hostname=test.example.com&myip=1.2.3.4")
if echo "$body" | grep -q 'badauth'; then
    pass "/nic/update no auth -> badauth"
else
    fail "/nic/update no auth -> badauth (got: ${body})"
fi

# 5. /nic/update with valid auth but unregistered hostname returns nohost
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
    "${BASE_URL}/nic/update?hostname=smoketest.example.com&myip=203.0.113.99")
if echo "$body" | grep -q 'nohost'; then
    pass "/nic/update unregistered hostname -> nohost"
else
    fail "/nic/update unregistered hostname -> nohost (got: ${body})"
fi

# 6. Static CSS returns 200
code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w '%{http_code}' "${BASE_URL}/static/style.css")
if [ "$code" = "200" ]; then
    pass "Static CSS returns 200"
else
    fail "Static CSS returns 200 (got ${code})"
fi

# 7. Dashboard redirects unauthenticated to login
code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w '%{http_code}' --max-redirs 0 "${BASE_URL}/admin/")
if [ "$code" = "302" ]; then
    pass "Dashboard redirects unauthenticated"
else
    fail "Dashboard redirects unauthenticated (got ${code})"
fi

# 8. Help redirects unauthenticated to login
code=$(curl "${CURL_OPTS[@]}" -o /dev/null -w '%{http_code}' --max-redirs 0 "${BASE_URL}/admin/help")
if [ "$code" = "302" ]; then
    pass "Help redirects unauthenticated"
else
    fail "Help redirects unauthenticated (got ${code})"
fi

# 9. Missing hostname returns 911
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" "${BASE_URL}/nic/update?myip=1.2.3.4")
if echo "$body" | grep -q '911'; then
    pass "/nic/update missing hostname -> 911"
else
    fail "/nic/update missing hostname -> 911 (got: ${body})"
fi

# 10. Invalid hostname returns notfqdn
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
    "${BASE_URL}/nic/update?hostname=-invalid..host&myip=1.2.3.4")
if echo "$body" | grep -q 'notfqdn'; then
    pass "/nic/update invalid hostname -> notfqdn"
else
    fail "/nic/update invalid hostname -> notfqdn (got: ${body})"
fi

# 11. Deprecated updatetype param is accepted (not an error)
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
    "${BASE_URL}/nic/update?hostname=smoketest.example.com&myip=203.0.113.99&updatetype=aws")
if echo "$body" | grep -qE '(nohost|good|nochg|911)'; then
    pass "/nic/update with updatetype param -> valid response (${body})"
else
    fail "/nic/update with updatetype param -> valid response (got: ${body})"
fi

echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
