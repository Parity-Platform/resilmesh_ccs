#!/bin/bash

# EV Charging Station Agent Entrypoint Script
# Determines which service to run based on environment variables

set -e

# Default values
SERVICE_TYPE=${SERVICE_TYPE:-"ev_charger"}
CHARGER_ID=${CHARGER_ID:-"EVCharge_001"}
WAZUH_MANAGER_IP=${WAZUH_MANAGER_IP:-"wazuh.manager"}
CHARGER_LOCATION=${CHARGER_LOCATION:-"Default_Location"}
SIMULATION_MODE=${SIMULATION_MODE:-"normal"}

echo "Starting EV Charging Station Security Agent..."
echo "Service Type: $SERVICE_TYPE"
echo "Charger ID: $CHARGER_ID"
echo "Wazuh Manager: $WAZUH_MANAGER_IP"
echo "Location: $CHARGER_LOCATION"
echo "Simulation Mode: $SIMULATION_MODE"

# Wait for Wazuh manager to be available
echo "Waiting for Wazuh manager to be available..."
while ! nc -z $WAZUH_MANAGER_IP 1514; do
    echo "Waiting for Wazuh manager at $WAZUH_MANAGER_IP:1514..."
    sleep 5
done
echo "Wazuh manager is available!"

# Wait for Wazuh API to be available
echo "Waiting for Wazuh API to be available..."
while ! nc -z $WAZUH_MANAGER_IP 55000; do
    echo "Waiting for Wazuh API at $WAZUH_MANAGER_IP:55000..."
    sleep 5
done
echo "Wazuh API is available!"

# Create a simple health check endpoint
create_health_endpoint() {
    mkdir -p /tmp/health
    cat > /tmp/health/server.py << EOF
import http.server
import socketserver
import json
from datetime import datetime

class HealthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            health_data = {
                "status": "healthy",
                "service": "$SERVICE_TYPE",
                "charger_id": "$CHARGER_ID",
                "timestamp": datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(health_data).encode())
        else:
            self.send_response(404)
            self.end_headers()

PORT = 8080
with socketserver.TCPServer(("", PORT), HealthHandler) as httpd:
    httpd.serve_forever()
EOF
    
    python /tmp/health/server.py &
    echo "Health endpoint started on port 8080"
}

# Start health endpoint in background
create_health_endpoint

# Determine which service to run
case $SERVICE_TYPE in
    "ev_charger")
        echo "Starting EV Charger Agent..."
        exec python ev_charger_agent.py
        ;;
    "traffic_generator")
        echo "Starting Network Traffic Generator..."
        exec python traffic_generator.py
        ;;
    "wazuh_integration")
        echo "Starting Wazuh Integration Service..."
        exec python wazuh_integration.py
        ;;
    *)
        echo "Unknown service type: $SERVICE_TYPE"
        echo "Available types: ev_charger, traffic_generator, wazuh_integration"
        exit 1
        ;;
esac