#!/bin/bash
# Test script for the SIEM ingest service

set -e

API_URL="${SIEM_API_URL:-http://localhost:8080}"
API_KEY="${SIEM_API_KEY:-sk_test_development}"

echo "=== SIEM Ingest Test Script ==="
echo "API URL: $API_URL"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

failure() {
    echo -e "${RED}✗ $1${NC}"
}

info() {
    echo -e "${YELLOW}→ $1${NC}"
}

# Test 1: Health check
info "Test 1: Health check"
HEALTH=$(curl -s "$API_URL/health")
if echo "$HEALTH" | grep -q '"status"'; then
    success "Health endpoint working"
    echo "  Response: $HEALTH"
else
    failure "Health endpoint failed"
    echo "  Response: $HEALTH"
fi
echo ""

# Test 2: Single event
info "Test 2: Single event ingestion"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RESPONSE=$(curl -s -X POST "$API_URL/v1/events" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"events\": [{
            \"timestamp\": \"$TIMESTAMP\",
            \"source\": {\"product\": \"test-client\", \"host\": \"test-host\"},
            \"action\": \"test.ping\",
            \"outcome\": \"success\",
            \"severity\": 1
        }]
    }")

if echo "$RESPONSE" | grep -q '"accepted":1'; then
    success "Single event accepted"
    echo "  Response: $RESPONSE"
else
    failure "Single event rejected"
    echo "  Response: $RESPONSE"
fi
echo ""

# Test 3: Batch events
info "Test 3: Batch event ingestion (3 events)"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RESPONSE=$(curl -s -X POST "$API_URL/v1/events" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"events\": [
            {\"timestamp\": \"$TIMESTAMP\", \"source\": {\"product\": \"boundary-daemon\"}, \"action\": \"auth.login\", \"outcome\": \"success\", \"severity\": 2},
            {\"timestamp\": \"$TIMESTAMP\", \"source\": {\"product\": \"boundary-daemon\"}, \"action\": \"session.created\", \"outcome\": \"success\", \"severity\": 3},
            {\"timestamp\": \"$TIMESTAMP\", \"source\": {\"product\": \"boundary-daemon\"}, \"action\": \"auth.failure\", \"outcome\": \"failure\", \"severity\": 5}
        ]
    }")

if echo "$RESPONSE" | grep -q '"accepted":3'; then
    success "Batch events accepted"
    echo "  Response: $RESPONSE"
else
    failure "Batch events failed"
    echo "  Response: $RESPONSE"
fi
echo ""

# Test 4: Event with actor
info "Test 4: Event with actor information"
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
RESPONSE=$(curl -s -X POST "$API_URL/v1/events" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"events\": [{
            \"timestamp\": \"$TIMESTAMP\",
            \"source\": {\"product\": \"boundary-daemon\", \"host\": \"prod-server-01\"},
            \"action\": \"session.created\",
            \"actor\": {
                \"type\": \"user\",
                \"id\": \"user_12345\",
                \"name\": \"john.doe\",
                \"ip_address\": \"192.168.1.100\"
            },
            \"target\": \"database:prod-db\",
            \"outcome\": \"success\",
            \"severity\": 3,
            \"metadata\": {
                \"session_id\": \"sess_abc123\",
                \"duration_ms\": 150
            }
        }]
    }")

if echo "$RESPONSE" | grep -q '"accepted":1'; then
    success "Event with actor accepted"
    echo "  Response: $RESPONSE"
else
    failure "Event with actor rejected"
    echo "  Response: $RESPONSE"
fi
echo ""

# Test 5: Invalid event (should be rejected)
info "Test 5: Invalid event (missing required fields)"
RESPONSE=$(curl -s -X POST "$API_URL/v1/events" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"events\": [{
            \"timestamp\": \"$TIMESTAMP\",
            \"source\": {\"product\": \"test\"},
            \"action\": \"INVALID ACTION FORMAT\",
            \"outcome\": \"success\",
            \"severity\": 1
        }]
    }")

if echo "$RESPONSE" | grep -q '"rejected":1'; then
    success "Invalid event correctly rejected"
    echo "  Response: $RESPONSE"
else
    failure "Invalid event was not rejected"
    echo "  Response: $RESPONSE"
fi
echo ""

# Test 6: Invalid severity
info "Test 6: Invalid severity (out of range)"
RESPONSE=$(curl -s -X POST "$API_URL/v1/events" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d "{
        \"events\": [{
            \"timestamp\": \"$TIMESTAMP\",
            \"source\": {\"product\": \"test\"},
            \"action\": \"test.event\",
            \"outcome\": \"success\",
            \"severity\": 15
        }]
    }")

if echo "$RESPONSE" | grep -q '"rejected":1'; then
    success "Invalid severity correctly rejected"
    echo "  Response: $RESPONSE"
else
    failure "Invalid severity was not rejected"
    echo "  Response: $RESPONSE"
fi
echo ""

# Test 7: Metrics endpoint
info "Test 7: Metrics endpoint"
METRICS=$(curl -s "$API_URL/metrics")
if echo "$METRICS" | grep -q 'siem_events_total'; then
    success "Metrics endpoint working"
    echo "$METRICS" | head -20
else
    failure "Metrics endpoint failed"
    echo "  Response: $METRICS"
fi
echo ""

# Final health check
info "Final health check"
curl -s "$API_URL/health" | python3 -m json.tool 2>/dev/null || curl -s "$API_URL/health"

echo ""
echo "=== Test Complete ==="
