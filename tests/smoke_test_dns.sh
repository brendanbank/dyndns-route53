#!/usr/bin/env bash
#
# DNS smoke test — creates, verifies, and deletes real DNS records
#
# Requires a running dyndns-route53 instance with backends configured
# and the test hostname registered to the test user.
#
# Usage:
#   source .env.smoketest && ./tests/smoke_test_dns.sh
#
# Or with arguments:
#   ./tests/smoke_test_dns.sh --host localhost:8080 --http \
#       --user admin --pass secret \
#       --hostname test.dyn.example.com --myip 203.0.113.42 \
#       --nameserver 8.8.8.8
#
# Environment variables (override with args):
#   SMOKETEST_HOST, SMOKETEST_RESOLVE, SMOKETEST_USERNAME,
#   SMOKETEST_PASSWORD, SMOKETEST_HOSTNAME, SMOKETEST_MYIP,
#   SMOKETEST_NAMESERVER
#

set -euo pipefail

# --- Defaults from env ---
HOST="${SMOKETEST_HOST:-}"
RESOLVE="${SMOKETEST_RESOLVE:-}"
USERNAME="${SMOKETEST_USERNAME:-}"
PASSWORD="${SMOKETEST_PASSWORD:-}"
TEST_HOSTNAME="${SMOKETEST_HOSTNAME:-}"
MYIP="${SMOKETEST_MYIP:-203.0.113.42}"
NAMESERVER="${SMOKETEST_NAMESERVER:-8.8.8.8}"
SCHEME="https"

# --- Parse args (override env) ---
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)       HOST="$2"; shift 2 ;;
        --user)       USERNAME="$2"; shift 2 ;;
        --pass)       PASSWORD="$2"; shift 2 ;;
        --hostname)   TEST_HOSTNAME="$2"; shift 2 ;;
        --myip)       MYIP="$2"; shift 2 ;;
        --nameserver) NAMESERVER="$2"; shift 2 ;;
        --http)       SCHEME="http"; shift ;;
        --resolve)    RESOLVE="$2"; shift 2 ;;
        *)            echo "Unknown option: $1"; exit 1 ;;
    esac
done

HOST="${HOST:?HOST is required (--host or \$SMOKETEST_HOST)}"
USERNAME="${USERNAME:?USERNAME is required (--user or \$SMOKETEST_USERNAME)}"
PASSWORD="${PASSWORD:?PASSWORD is required (--pass or \$SMOKETEST_PASSWORD)}"
TEST_HOSTNAME="${TEST_HOSTNAME:?HOSTNAME is required (--hostname or \$SMOKETEST_HOSTNAME)}"

BASE_URL="${SCHEME}://${HOST}"
PASS_COUNT=0
FAIL_COUNT=0

# Build curl opts
CURL_OPTS=(-s -k)
if [ -n "$RESOLVE" ]; then
    CURL_HOSTNAME="${HOST%%:*}"
    PORT="${HOST##*:}"
    if [ "$PORT" = "$CURL_HOSTNAME" ]; then
        if [ "$SCHEME" = "https" ]; then PORT=443; else PORT=80; fi
    fi
    CURL_OPTS+=(--resolve "${CURL_HOSTNAME}:${PORT}:${RESOLVE}")
fi

pass() {
    echo "  PASS  $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo "  FAIL  $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

dns_lookup() {
    # Resolve A record for $1 via $NAMESERVER, return IP or empty string
    dig +short @"${NAMESERVER}" "$1" A 2>/dev/null | head -1
}

dns_lookup_retry() {
    # Retry dns_lookup up to $2 times (default 6) with $3 sec delay (default 5)
    local hostname="$1"
    local expected="${2:-}"
    local retries="${3:-6}"
    local delay="${4:-5}"
    local ip
    for ((i = 1; i <= retries; i++)); do
        ip=$(dns_lookup "$hostname")
        if [ -z "$expected" ] && [ -z "$ip" ]; then
            echo ""
            return 0
        elif [ -n "$expected" ] && [ "$ip" = "$expected" ]; then
            echo "$ip"
            return 0
        fi
        if [ "$i" -lt "$retries" ]; then
            echo "  retry ${i}/${retries}: got '${ip:-<empty>}', waiting ${delay}s ..." >&2
            sleep "$delay"
        fi
    done
    echo "$ip"
}

cleanup() {
    # Best-effort delete of the test record on exit
    echo
    echo "Cleaning up: deleting ${TEST_HOSTNAME} ..."
    body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
        "${BASE_URL}/nic/delete?hostname=${TEST_HOSTNAME}")
    echo "  cleanup response: ${body}"
    # Wait for DNS propagation and verify
    ip=$(dns_lookup_retry "${TEST_HOSTNAME}" "" 3 3)
    if [ -z "$ip" ]; then
        echo "  cleanup: DNS record removed"
    else
        echo "  cleanup: WARNING — DNS record still resolves to ${ip}"
    fi
}

echo "DNS smoke test against ${BASE_URL}${RESOLVE:+ (resolve via ${RESOLVE})}"
echo "  hostname:   ${TEST_HOSTNAME}"
echo "  myip:       ${MYIP}"
echo "  nameserver: ${NAMESERVER}"
echo

# Always clean up test records, even on failure
trap cleanup EXIT

# --- Step 1: Delete any pre-existing record ---
echo "--- Pre-cleanup ---"
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
    "${BASE_URL}/nic/delete?hostname=${TEST_HOSTNAME}")
echo "  pre-cleanup response: ${body}"

# Verify record does not exist
ip=$(dns_lookup_retry "${TEST_HOSTNAME}" "")
if [ -z "$ip" ]; then
    pass "Pre-cleanup: no DNS record for ${TEST_HOSTNAME}"
else
    fail "Pre-cleanup: ${TEST_HOSTNAME} still resolves to ${ip}"
fi

# --- Step 2: Create A record ---
echo
echo "--- Create record ---"
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
    "${BASE_URL}/nic/update?hostname=${TEST_HOSTNAME}&myip=${MYIP}")
if echo "$body" | grep -q 'good'; then
    pass "/nic/update -> good (${body})"
else
    fail "/nic/update -> expected good (got: ${body})"
fi

# --- Step 3: Verify A record exists ---
echo
echo "--- Verify record ---"
ip=$(dns_lookup_retry "${TEST_HOSTNAME}" "${MYIP}")
if [ "$ip" = "$MYIP" ]; then
    pass "DNS A record resolves to ${MYIP}"
else
    fail "DNS A record expected ${MYIP} (got: ${ip:-<empty>})"
fi

# --- Step 4: Update same IP should return nochg ---
echo
echo "--- Update same IP (nochg) ---"
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
    "${BASE_URL}/nic/update?hostname=${TEST_HOSTNAME}&myip=${MYIP}")
if echo "$body" | grep -q 'nochg'; then
    pass "/nic/update same IP -> nochg (${body})"
else
    fail "/nic/update same IP -> expected nochg (got: ${body})"
fi

# --- Step 5: Delete the record ---
echo
echo "--- Delete record ---"
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
    "${BASE_URL}/nic/delete?hostname=${TEST_HOSTNAME}")
if echo "$body" | grep -q 'good'; then
    pass "/nic/delete -> good (${body})"
else
    fail "/nic/delete -> expected good (got: ${body})"
fi

# --- Step 6: Verify record is gone ---
echo
echo "--- Verify deletion ---"
ip=$(dns_lookup_retry "${TEST_HOSTNAME}" "")
if [ -z "$ip" ]; then
    pass "DNS A record deleted (no longer resolves)"
else
    fail "DNS A record still resolves to ${ip} after delete"
fi

# --- Step 7: Delete again should return good or nochg ---
# Note: nsupdate (BIND) accepts delete-of-nonexistent without error, so
# backends may return "good" even when the record is already gone.
echo
echo "--- Delete again (nochg/good) ---"
body=$(curl "${CURL_OPTS[@]}" -u "${USERNAME}:${PASSWORD}" \
    "${BASE_URL}/nic/delete?hostname=${TEST_HOSTNAME}")
if echo "$body" | grep -qE '(nochg|good)'; then
    pass "/nic/delete already gone -> ${body}"
else
    fail "/nic/delete already gone -> expected nochg or good (got: ${body})"
fi

# Disable the EXIT trap cleanup since we've already verified deletion
trap - EXIT

echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"

if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
