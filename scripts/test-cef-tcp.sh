#!/bin/bash
# Test script for CEF TCP ingestion

SIEM_HOST="${SIEM_HOST:-localhost}"
SIEM_PORT="${SIEM_PORT:-5515}"

echo "Sending CEF events to $SIEM_HOST:$SIEM_PORT via TCP..."

{
    echo 'CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success'
    echo 'CEF:0|Boundary|boundary-daemon|1.0.0|400|Auth Failed|7|src=10.0.0.50 suser=attacker outcome=failure'
    echo 'CEF:0|Boundary|boundary-daemon|1.0.0|200|Login Success|2|src=192.168.1.100 suser=admin outcome=success'
    echo 'CEF:0|SecurityVendor|Firewall|1.0|TRAFFIC|Connection Allowed|1|src=192.168.1.50 dst=8.8.8.8 dpt=443 act=allow outcome=success'
    echo 'CEF:0|SecurityVendor|IDS|2.0|THREAT|Suspicious Activity|8|src=10.0.0.99 dst=192.168.1.1 act=alert msg=Port scan detected'
} | nc "$SIEM_HOST" "$SIEM_PORT"

echo ""
echo "Done! Sent 5 CEF events via TCP"
echo ""
echo "Check metrics at: http://$SIEM_HOST:8080/metrics"
