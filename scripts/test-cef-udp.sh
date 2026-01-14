#!/bin/bash
# Test script for CEF UDP ingestion

SIEM_HOST="${SIEM_HOST:-localhost}"
SIEM_PORT="${SIEM_PORT:-5514}"

echo "Sending CEF events to $SIEM_HOST:$SIEM_PORT via UDP..."

# Session created
echo 'CEF:0|Boundary|boundary-daemon|1.0.0|100|Session Created|3|src=192.168.1.10 suser=admin dhost=db-prod-01 outcome=success' | nc -u -w1 "$SIEM_HOST" "$SIEM_PORT"
echo "Sent: Session Created"

# Authentication failure
echo 'CEF:0|Boundary|boundary-daemon|1.0.0|400|Authentication Failed|7|src=10.0.0.50 suser=unknown dhost=api-server outcome=failure reason=invalid_password' | nc -u -w1 "$SIEM_HOST" "$SIEM_PORT"
echo "Sent: Authentication Failed"

# High severity threat
echo 'CEF:0|SecurityVendor|IDS|2.0|THREAT|Malware Detected|9|src=203.0.113.50 dst=192.168.1.100 act=blocked filePath=/tmp/evil.exe fileHash=abc123' | nc -u -w1 "$SIEM_HOST" "$SIEM_PORT"
echo "Sent: Malware Detected"

# Login success
echo 'CEF:0|Boundary|boundary-daemon|1.0.0|200|Login Success|2|src=192.168.1.100 suser=admin outcome=success' | nc -u -w1 "$SIEM_HOST" "$SIEM_PORT"
echo "Sent: Login Success"

# Access denied
echo 'CEF:0|Boundary|boundary-daemon|1.0.0|501|Access Denied|6|src=192.168.1.200 suser=guest dhost=prod-db-01 outcome=failure reason=unauthorized' | nc -u -w1 "$SIEM_HOST" "$SIEM_PORT"
echo "Sent: Access Denied"

echo ""
echo "Done! Sent 5 CEF events via UDP"
echo ""
echo "Check metrics at: http://$SIEM_HOST:8080/metrics"
