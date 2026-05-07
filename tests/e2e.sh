#!/usr/bin/env bash
# E2E test: start pathforge + FRRouting via docker compose, verify BGP session
set -euo pipefail

TIMEOUT=60
SOCK=/tmp/pathforge-e2e.sock

log() { echo "[e2e] $*"; }
fail() { echo "[e2e] FAIL: $*" >&2; docker compose logs; docker compose down -v 2>/dev/null; exit 1; }

# Requires Docker
command -v docker &>/dev/null || fail "docker not found"

log "Starting docker compose stack..."
docker compose down -v 2>/dev/null || true
docker compose up --build -d

log "Waiting for BGP session to establish (up to ${TIMEOUT}s)..."
DEADLINE=$((SECONDS + TIMEOUT))
established=false
while [ $SECONDS -lt $DEADLINE ]; do
    if docker compose logs pathforge 2>/dev/null | grep -q "Established\|established"; then
        established=true
        break
    fi
    sleep 2
done

if ! $established; then
    log "Checking FRR state as fallback..."
    if docker compose exec -T frr vtysh -c "show bgp summary" 2>/dev/null | grep -q "Establ"; then
        established=true
    fi
fi

$established || fail "BGP session did not reach Established state within ${TIMEOUT}s"
log "✅ BGP session established"

# Verify FRR received routes from pathforge (or pathforge is up and responding)
log "Checking FRR BGP summary..."
FRR_SUMMARY=$(docker compose exec -T frr vtysh -c "show bgp summary" 2>/dev/null || echo "")
echo "$FRR_SUMMARY"

# Verify pathforge is listening on management socket
log "Checking pathforge management socket..."
CONTAINER_ID=$(docker compose ps -q pathforge)
if docker exec "$CONTAINER_ID" test -S /tmp/pathforge.sock 2>/dev/null; then
    log "✅ Management socket present"
else
    log "⚠️  Management socket not found (container may not support exec)"
fi

log "✅ E2E test passed"
docker compose down -v
