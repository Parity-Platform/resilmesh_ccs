#!/bin/bash

# EV Charging Station SIEM Deployment Script
# This script sets up the complete Wazuh SIEM environment with EV charging station monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WAZUH_VERSION="4.7.0"
PROJECT_NAME="ev-charger-siem"
BASE_DIR="$(pwd)"
CONFIG_DIR="$BASE_DIR/config"
AGENTS_DIR="$BASE_DIR/ev-agents"
LOGS_DIR="$BASE_DIR/logs"

print_header() {
    echo -e "${BLUE}"
    echo "==============================================="
    echo "  EV Charging Station SIEM Deployment"
    echo "  Wazuh Version: $WAZUH_VERSION"
    echo "==============================================="
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if docker is installed
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if docker-compose is installed
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check available disk space (minimum 5GB)
    available_space=$(df . | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 5242880 ]; then
        print_warning "Less than 5GB disk space available. Deployment may fail."
    fi
    
    # Check available memory (minimum 4GB)
    available_memory=$(free -m | awk 'NR==2{printf "%.0f", $7/1024}')
    if [ "$available_memory" -lt 4 ]; then
        print_warning "Less than 4GB RAM available. Performance may be affected."
    fi
    
    print_status "Prerequisites check completed."
}

create_directory_structure() {
    print_status "Creating directory structure..."
    
    mkdir -p "$CONFIG_DIR"/{wazuh_cluster,wazuh_indexer,wazuh_dashboard,wazuh_indexer_ssl_certs}
    mkdir -p "$AGENTS_DIR"
    mkdir -p "$LOGS_DIR"/{ev-charger,wazuh,traffic}
    
    print_status "Directory structure created."
}

generate_ssl_certificates() {
    print_status "Generating SSL certificates for Wazuh..."
    
    local cert_dir="$CONFIG_DIR/wazuh_indexer_ssl_certs"
    
    # Generate CA certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$cert_dir/root-ca-key.pem" \
        -out "$cert_dir/root-ca.pem" \
        -subj "/C=US/ST=CA/L=San Francisco/O=EV Charger SIEM/CN=wazuh-ca" 2>/dev/null || {
        print_warning "OpenSSL not available. Using pre-generated certificates."
        create_dummy_certificates "$cert_dir"
    }
    
    # Generate certificates for each component
    local components=("wazuh.manager" "wazuh.indexer" "wazuh.dashboard")
    
    for component in "${components[@]}"; do
        openssl req -nodes -newkey rsa:2048 \
            -keyout "$cert_dir/$component-key.pem" \
            -out "$cert_dir/$component.csr" \
            -subj "/C=US/ST=CA/L=San Francisco/O=EV Charger SIEM/CN=$component" 2>/dev/null || continue
            
        openssl x509 -req -days 365 \
            -in "$cert_dir/$component.csr" \
            -CA "$cert_dir/root-ca.pem" \
            -CAkey "$cert_dir/root-ca-key.pem" \
            -CAcreateserial \
            -out "$cert_dir/$component.pem" 2>/dev/null || continue
            
        rm -f "$cert_dir/$component.csr"
    done
    
    # Create admin certificates
    cp "$cert_dir/wazuh.indexer.pem" "$cert_dir/admin.pem" 2>/dev/null || true
    cp "$cert_dir/wazuh.indexer-key.pem" "$cert_dir/admin-key.pem" 2>/dev/null || true
    
    # Copy root CA for manager
    cp "$cert_dir/root-ca.pem" "$cert_dir/root-ca-manager.pem" 2>/dev/null || true
    
    print_status "SSL certificates generated."
}

create_dummy_certificates() {
    local cert_dir="$1"
    print_warning "Creating dummy certificates for demo purposes."
    
    # Create dummy certificate files
    echo "-----BEGIN CERTIFICATE-----" > "$cert_dir/root-ca.pem"
    echo "MIICljCCAX4CCQDummy certificate data for demo purposes only" >> "$cert_dir/root-ca.pem"
    echo "-----END CERTIFICATE-----" >> "$cert_dir/root-ca.pem"
    
    # Copy for all components
    local files=("wazuh.manager.pem" "wazuh.indexer.pem" "wazuh.dashboard.pem" "admin.pem" "root-ca-manager.pem")
    for file in "${files[@]}"; do
        cp "$cert_dir/root-ca.pem" "$cert_dir/$file"
    done
    
    # Create dummy key files
    echo "-----BEGIN PRIVATE KEY-----" > "$cert_dir/dummy-key.pem"
    echo "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDummy key data" >> "$cert_dir/dummy-key.pem"
    echo "-----END PRIVATE KEY-----" >> "$cert_dir/dummy-key.pem"
    
    local key_files=("wazuh.manager-key.pem" "wazuh.indexer-key.pem" "wazuh.dashboard-key.pem" "admin-key.pem")
    for file in "${key_files[@]}"; do
        cp "$cert_dir/dummy-key.pem" "$cert_dir/$file"
    done
}

create_wazuh_configs() {
    print_status "Creating Wazuh configuration files..."
    
    # Wazuh Manager configuration
    cat > "$CONFIG_DIR/wazuh_cluster/wazuh_manager.conf" << 'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@localhost</email_from>
    <email_to>admin@localhost</email_to>
    <hostname>wazuh-manager</hostname>
    <email_maxperhour>12</email_maxperhour>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>

  <cluster>
    <name>wazuh</name>
    <node_name>worker</node_name>
    <node_type>worker</node_type>
    <key></key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>wazuh.manager</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>yes</disabled>
  </cluster>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/ev-charger/*.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/traffic/*.log</location>
  </localfile>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
  </ruleset>

  <rule_test>
    <enabled>yes</enabled>
    <threads>1</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>15m</session_timeout>
  </rule_test>

  <integration>
    <name>virustotal</name>
    <api_key>YOUR_VIRUS_TOTAL_API_KEY</api_key>
    <group>syscheck,</group>
    <alert_format>json</alert_format>
  </integration>

  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <min_full_scan_interval>6h</min_full_scan_interval>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <os>jammy</os>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>

</ossec_config>
EOF

    # Wazuh Indexer configuration
    cat > "$CONFIG_DIR/wazuh_indexer/wazuh.indexer.yml" << 'EOF'
network.host: "0.0.0.0"
node.name: "wazuh.indexer"
cluster.initial_master_nodes:
  - "wazuh.indexer"
cluster.name: "wazuh-cluster"
node.max_local_storage_nodes: 3
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

bootstrap.memory_lock: true

plugins.security.ssl.transport.pemcert_filepath: certs/wazuh.indexer.pem
plugins.security.ssl.transport.pemkey_filepath: certs/wazuh.indexer.key
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/wazuh.indexer.pem
plugins.security.ssl.http.pemkey_filepath: certs/wazuh.indexer.key
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.pem
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US
plugins.security.check_snapshot_restore_write_privileges: true
plugins.security.enable_snapshot_restore_privilege: true
plugins.security.system_indices.enabled: true
plugins.security.system_indices.indices:
  [
    ".opendistro-alerting-config",
    ".opendistro-alerting-alert*",
    ".opendistro-anomaly-results*",
    ".opendistro-anomaly-detector*",
    ".opendistro-anomaly-checkpoints",
    ".opendistro-anomaly-detection-state",
    ".opendistro-reports-*",
    ".opendistro-notifications-*",
    ".opendistro-notebooks",
    ".opensearch-observability",
    ".opendistro-asynchronous-search-response*",
    ".replication-metadata-store",
  ]
compatibility.override_main_response_version: true
EOF

    # Wazuh Indexer internal users
    cat > "$CONFIG_DIR/wazuh_indexer/internal_users.yml" << 'EOF'
---
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$2a$12$VcCDgh2NDk07JGN0rjGbM.Ad41qVR/YFJcgHp0UGns5JDymv..TOG"
  reserved: true
  backend_roles:
  - "admin"
  description: "Demo admin user"

kibanaserver:
  hash: "$2a$12$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H."
  reserved: true
  description: "Demo kibanaserver user"

kibanaro:
  hash: "$2a$12$JJSXNfTowz7Uu5ttXfeYpeYE0arACvcwlPBStB1F.MI7f0U9Z4DGC"
  reserved: false
  backend_roles:
  - "kibanauser"
  - "readall"
  attributes:
    attribute1: "value1"
    attribute2: "value2"
    attribute3: "value3"
  description: "Demo kibanaro user"

logstash:
  hash: "$2a$12$u1ShR4l4uBS3Uv59Pa2y5.1uQuZBrZtmNfqB3iM/.jL0XoV9sghS2"
  reserved: false
  backend_roles:
  - "logstash"
  description: "Demo logstash user"

readall:
  hash: "$2a$12$ae4ycwzwvLtZxwZ82RmiEunBbIPiAmGZduBAjKN0TXdwQFtCwARz2"
  reserved: false
  backend_roles:
  - "readall"
  description: "Demo readall user"

snapshotrestore:
  hash: "$2y$12$DpwmetHKwgYnorbgdvORCenv4NAK8cPUg8AI6pxLCuWf/ALc0.v7W"
  reserved: false
  backend_roles:
  - "snapshotrestore"
  description: "Demo snapshotrestore user"
EOF

    # Wazuh Dashboard configuration
    cat > "$CONFIG_DIR/wazuh_dashboard/opensearch_dashboards.yml" << 'EOF'
server.host: 0.0.0.0
server.port: 5601
opensearch.hosts: https://wazuh.indexer:9200
opensearch.ssl.verificationMode: certificate
opensearch.username: kibanaserver
opensearch.password: kibanaserver
opensearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
server.ssl.certificate: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
opensearch.ssl.certificateAuthorities: ["/usr/share/wazuh-dashboard/certs/root-ca.pem"]
uiSettings.overrides.defaultRoute: /app/wazuh
opensearch_security.auth.anonymous_auth_enabled: false
logging.silent: false
logging.quiet: false
logging.verbose: true
newsfeed.enabled: false
telemetry.optIn: false
telemetry.enabled: false
wazuh.monitoring.enabled: true
wazuh.monitoring.frequency: 900
wazuh.monitoring.shards: 2
wazuh.monitoring.replicas: 0
EOF

    # Wazuh Dashboard API configuration
    cat > "$CONFIG_DIR/wazuh_dashboard/wazuh.yml" << 'EOF'
hosts:
  - default:
     url: "https://wazuh.manager"
     port: 55000
     username: wazuh-wui
     password: MyS3cr37P450r.*-
     run_as: false
pattern: "wazuh-alerts-*"
checks.pattern: true
checks.template: true
checks.api: true
checks.setup: true
checks.fields: true
checks.metaFields: true
checks.timeFilter: true
checks.maxBuckets: true
timeout: 20000
api.selector: true
ip.selector: true
ip.ignore: []
xpack.rbac.enabled: true
wazuh.monitoring.enabled: true
wazuh.monitoring.frequency: 900
wazuh.monitoring.shards: 2
wazuh.monitoring.replicas: 0
admin: true
hideManagerAlerts: false
logs.level: info
enrollPassword: ""
cron.prefix: wazuh
cron.statistics.status: true
cron.statistics.apis: []
cron.statistics.interval: 0 */5 * * * *
cron.statistics.index.name: statistics
cron.statistics.index.creation: w
cron.statistics.index.shards: 2
cron.statistics.index.replicas: 0
alerts.sample.prefix: wazuh-alerts-4.x-
EOF

    print_status "Wazuh configuration files created."
}

create_agent_files() {
    print_status "Creating EV agent files..."
    
    # Copy Python files to agents directory (they should already exist as artifacts)
    # This is just a placeholder - in real deployment, you'd copy the actual files
    
    # Create Dockerfile in agents directory
    cp docker-compose.yml "$BASE_DIR/" 2>/dev/null || true
    
    # Create .env file for docker-compose
    cat > "$BASE_DIR/.env" << EOF
WAZUH_VERSION=$WAZUH_VERSION
COMPOSE_PROJECT_NAME=$PROJECT_NAME
EOF
    
    print_status "EV agent files created."
}

deploy_system() {
    print_status "Deploying the EV Charging Station SIEM system..."
    
    # Check if ports are available
    local ports=(443 9200 1514 1515 55000)
    for port in "${ports[@]}"; do
        if netstat -ln 2>/dev/null | grep -q ":$port "; then
            print_warning "Port $port is already in use. Deployment may fail."
        fi
    done
    
    # Start the system
    docker-compose up -d
    
    print_status "System deployment initiated."
}

wait_for_services() {
    print_status "Waiting for services to start..."
    
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if curl -k -s https://localhost:443 >/dev/null 2>&1; then
            print_status "Wazuh Dashboard is ready!"
            break
        fi
        
        echo -n "."
        sleep 5
        ((attempt++))
    done
    
    if [ $attempt -eq $max_attempts ]; then
        print_warning "Services may not be fully ready. Check logs with: docker-compose logs"
    fi
}

show_access_information() {
    print_status "Deployment completed! Access information:"
    echo ""
    echo -e "${GREEN}Wazuh Dashboard:${NC} https://localhost"
    echo -e "${GREEN}Username:${NC} admin"
    echo -e "${GREEN}Password:${NC} SecretPassword"
    echo ""
    echo -e "${GREEN}Wazuh API:${NC} https://localhost:55000"
    echo -e "${GREEN}API Username:${NC} wazuh-wui"
    echo -e "${GREEN}API Password:${NC} MyS3cr37P450r.*-"
    echo ""
    echo -e "${YELLOW}Note:${NC} SSL certificates are self-signed. Accept the security warning in your browser."
    echo ""
    echo -e "${BLUE}Useful commands:${NC}"
    echo "  View logs: docker-compose logs -f"
    echo "  Stop system: docker-compose down"
    echo "  Restart: docker-compose restart"
    echo "  View EV charger logs: docker-compose logs ev-charger-1"
}

create_monitoring_dashboard() {
    print_status "Creating monitoring helper scripts..."
    
    cat > "$BASE_DIR/monitor.sh" << 'EOF'
#!/bin/bash
# EV Charging Station Monitoring Helper

case "$1" in
    "status")
        echo "=== Container Status ==="
        docker-compose ps
        echo ""
        echo "=== Service Health ==="
        curl -k -s https://localhost:443 >/dev/null && echo "✓ Dashboard: OK" || echo "✗ Dashboard: ERROR"
        curl -k -s https://localhost:55000 >/dev/null && echo "✓ API: OK" || echo "✗ API: ERROR"
        ;;
    "logs")
        service=${2:-""}
        if [ -z "$service" ]; then
            echo "Available services:"
            docker-compose ps --services
            echo "Usage: ./monitor.sh logs <service_name>"
        else
            docker-compose logs -f "$service"
        fi
        ;;
    "alerts")
        echo "=== Recent Security Alerts ==="
        docker-compose exec wazuh.manager tail -n 20 /var/ossec/logs/alerts/alerts.json
        ;;
    "restart")
        service=${2:-""}
        if [ -z "$service" ]; then
            docker-compose restart
        else
            docker-compose restart "$service"
        fi
        ;;
    *)
        echo "EV Charging Station SIEM Monitor"
        echo "Usage: $0 {status|logs|alerts|restart} [service]"
        echo ""
        echo "Commands:"
        echo "  status              - Show system status"
        echo "  logs [service]      - Show logs for service"
        echo "  alerts              - Show recent security alerts" 
        echo "  restart [service]   - Restart service or all services"
        ;;
esac
EOF
    
    chmod +x "$BASE_DIR/monitor.sh"
    
    print_status "Monitoring scripts created."
}

cleanup_on_error() {
    print_error "Deployment failed. Cleaning up..."
    docker-compose down --remove-orphans 2>/dev/null || true
    exit 1
}

main() {
    print_header
    
    # Set trap for cleanup on error
    trap cleanup_on_error ERR
    
    check_prerequisites
    create_directory_structure
    generate_ssl_certificates
    create_wazuh_configs
    create_agent_files
    deploy_system
    wait_for_services
    create_monitoring_dashboard
    show_access_information
    
    print_status "EV Charging Station SIEM deployment completed successfully!"
}

# Run main function
main "$@"