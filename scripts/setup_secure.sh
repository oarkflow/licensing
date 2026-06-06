#!/bin/bash

# Legacy secure setup reference.
# New single-node SQLite deployments should use docs/PRODUCTION_SQLITE_RUNBOOK.md
# and scripts/local_single_node_setup.sh instead.

set -e

echo "=========================================="
echo "Secure License Server Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="${INSTALL_DIR:-/opt/licensing}"
DATA_DIR="${DATA_DIR:-$INSTALL_DIR/data}"
KEYS_DIR="${KEYS_DIR:-$INSTALL_DIR/keys}"
CERTS_DIR="${CERTS_DIR:-$INSTALL_DIR/certs}"
LOGS_DIR="${LOGS_DIR:-$INSTALL_DIR/logs}"
BACKUP_DIR="${BACKUP_DIR:-$INSTALL_DIR/backups}"

echo -e "${YELLOW}Installation directory: $INSTALL_DIR${NC}"

# Function to print success
print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

# Function to print error
print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Function to print info
print_info() {
    echo -e "${YELLOW}→${NC} $1"
}

# Check if running as root (for production installation)
if [ "$EUID" -eq 0 ] && [ "$ALLOW_ROOT" != "true" ]; then
    print_error "Please do not run as root unless setting ALLOW_ROOT=true"
    exit 1
fi

# Step 1: Create directory structure
print_info "Creating directory structure..."
mkdir -p "$DATA_DIR"
mkdir -p "$KEYS_DIR"
mkdir -p "$CERTS_DIR"
mkdir -p "$LOGS_DIR"
mkdir -p "$BACKUP_DIR"
print_success "Directories created"

# Step 2: Set secure permissions
print_info "Setting secure permissions..."
chmod 700 "$KEYS_DIR"
chmod 700 "$DATA_DIR"
chmod 755 "$CERTS_DIR"
chmod 755 "$LOGS_DIR"
chmod 700 "$BACKUP_DIR"
print_success "Permissions set"

# Step 3: Generate encryption key
print_info "Generating encryption key..."
if [ ! -f "$KEYS_DIR/encryption.key" ]; then
    # Generate 32-byte (256-bit) encryption key
    openssl rand -base64 32 > "$KEYS_DIR/encryption.key"
    chmod 600 "$KEYS_DIR/encryption.key"
    print_success "Encryption key generated"
else
    print_info "Encryption key already exists, skipping"
fi

# Step 4: Generate signing keys (Ed25519)
print_info "Generating signing keys..."
if [ ! -f "$KEYS_DIR/signing.key" ]; then
    # Generate Ed25519 key pair
    openssl genpkey -algorithm Ed25519 -out "$KEYS_DIR/signing.key"
    openssl pkey -in "$KEYS_DIR/signing.key" -pubout -out "$KEYS_DIR/signing.pub"
    chmod 600 "$KEYS_DIR/signing.key"
    chmod 644 "$KEYS_DIR/signing.pub"
    print_success "Signing keys generated"
else
    print_info "Signing keys already exist, skipping"
fi

# Step 5: Generate TLS certificates (self-signed for development)
print_info "Generating TLS certificates..."
if [ ! -f "$CERTS_DIR/server.crt" ]; then
    openssl req -x509 -newkey rsa:4096 -nodes \
        -keyout "$CERTS_DIR/server.key" \
        -out "$CERTS_DIR/server.crt" \
        -days 365 \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1"

    chmod 600 "$CERTS_DIR/server.key"
    chmod 644 "$CERTS_DIR/server.crt"
    print_success "TLS certificates generated"
    print_info "NOTE: For production, replace with CA-signed certificates"
else
    print_info "TLS certificates already exist, skipping"
fi

# Step 6: Create environment file
print_info "Creating environment configuration..."
cat > "$INSTALL_DIR/.env" << EOF
# Database
DB_PATH=$DATA_DIR/licensing.db

# Cryptography
SIGNING_ALGORITHM=ed25519
ENCRYPTION_KEY_PATH=$KEYS_DIR/encryption.key
KEY_ROTATION_ENABLED=true
KEY_ROTATION_INTERVAL=2160h  # 90 days
KEY_RETENTION_PERIOD=8760h   # 365 days

# Authentication
REQUIRE_AUTHENTICATION=true
SESSION_TIMEOUT=8h
MAX_LOGIN_ATTEMPTS=3

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=30
RATE_LIMIT_PER_HOUR=500

# Audit
AUDIT_ENABLED=true
AUDIT_ASYNC=true
AUDIT_BUFFER_SIZE=5000
AUDIT_SIGNING_ENABLED=true

# Integrity
TAMPER_DETECTION_ENABLED=true
INTEGRITY_CHECK_INTERVAL=5m
DEBUGGER_DETECTION=true

# Network Security
TLS_ENABLED=true
TLS_CERT_FILE=$CERTS_DIR/server.crt
TLS_KEY_FILE=$CERTS_DIR/server.key
TLS_CLIENT_CA_FILE=
REQUIRE_CLIENT_CERT=false

# Monitoring
METRICS_ENABLED=true
ALERTS_ENABLED=true
HEALTH_CHECK_ENABLED=true
HEALTH_CHECK_INTERVAL=30s

# Server
SERVER_ADDRESS=:8443
READ_TIMEOUT=10s
WRITE_TIMEOUT=10s
SHUTDOWN_TIMEOUT=30s

# Logging
LOG_LEVEL=info
LOG_FILE=$LOGS_DIR/server.log
EOF
chmod 600 "$INSTALL_DIR/.env"
print_success "Environment file created"

# Step 7: Initialize database
print_info "Initializing database..."
if [ ! -f "$DATA_DIR/licensing.db" ]; then
    # Build and run the server briefly to initialize database
    cd "$(dirname "$0")" || exit 1
    go build -o "$INSTALL_DIR/licensing-server" ./cmd/main.go

    # Run database migrations (if you have migration tool)
    # ./licensing-server migrate up

    print_success "Database initialized"
else
    print_info "Database already exists, skipping"
fi

# Step 8: Create systemd service file (optional)
if command -v systemctl &> /dev/null; then
    print_info "Creating systemd service..."
    cat > /tmp/licensing.service << EOF
[Unit]
Description=Secure Licensing Server
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=$INSTALL_DIR/licensing-server
Restart=always
RestartSec=10
StandardOutput=append:$LOGS_DIR/server.log
StandardError=append:$LOGS_DIR/error.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOGS_DIR $BACKUP_DIR

[Install]
WantedBy=multi-user.target
EOF

    if [ "$ALLOW_ROOT" = "true" ]; then
        sudo mv /tmp/licensing.service /etc/systemd/system/
        sudo systemctl daemon-reload
        print_success "Systemd service created"
        print_info "Start service with: sudo systemctl start licensing"
        print_info "Enable on boot with: sudo systemctl enable licensing"
    else
        print_info "Systemd service file created at /tmp/licensing.service"
        print_info "Install with: sudo mv /tmp/licensing.service /etc/systemd/system/ && sudo systemctl daemon-reload"
    fi
fi

# Step 9: Create backup script
print_info "Creating backup script..."
cat > "$INSTALL_DIR/backup.sh" << 'EOF'
#!/bin/bash
BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/backup_$TIMESTAMP.tar.gz"

echo "Creating backup: $BACKUP_FILE"
tar -czf "$BACKUP_FILE" \
    --exclude='./backups' \
    --exclude='./logs/*.log' \
    ./data ./keys

# Keep only last 7 backups
ls -t "$BACKUP_DIR"/backup_*.tar.gz | tail -n +8 | xargs -r rm

echo "Backup completed: $BACKUP_FILE"
EOF
chmod +x "$INSTALL_DIR/backup.sh"
print_success "Backup script created"

# Step 10: Create health check script
print_info "Creating health check script..."
cat > "$INSTALL_DIR/health_check.sh" << 'EOF'
#!/bin/bash
HEALTH_URL="${HEALTH_URL:-https://localhost:8443/health}"

response=$(curl -k -s -o /dev/null -w "%{http_code}" "$HEALTH_URL")

if [ "$response" = "200" ]; then
    echo "✓ Server is healthy"
    exit 0
else
    echo "✗ Server is unhealthy (HTTP $response)"
    exit 1
fi
EOF
chmod +x "$INSTALL_DIR/health_check.sh"
print_success "Health check script created"

# Step 11: Security summary
echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
print_success "Directory structure created"
print_success "Encryption keys generated"
print_success "TLS certificates created"
print_success "Configuration files created"
echo ""
print_info "IMPORTANT: Please review the following:"
echo "  1. Update $INSTALL_DIR/.env with your specific settings"
echo "  2. For production, replace TLS certificates with CA-signed ones"
echo "  3. Set up firewall rules to restrict access"
echo "  4. Configure backup schedule (see backup.sh)"
echo "  5. Review and adjust rate limits and timeouts"
echo ""
print_info "Next steps:"
echo "  1. Source environment: source $INSTALL_DIR/.env"
echo "  2. Start server: $INSTALL_DIR/licensing-server"
echo "  3. Check health: $INSTALL_DIR/health_check.sh"
echo ""
print_info "Security checklist:"
echo "  ☐ Keys directory permissions (700): $(stat -c %a "$KEYS_DIR")"
echo "  ☐ Data directory permissions (700): $(stat -c %a "$DATA_DIR")"
echo "  ☐ Environment file permissions (600): $(stat -c %a "$INSTALL_DIR/.env")"
echo "  ☐ TLS enabled: $(grep TLS_ENABLED "$INSTALL_DIR/.env" | cut -d= -f2)"
echo "  ☐ Audit enabled: $(grep AUDIT_ENABLED "$INSTALL_DIR/.env" | cut -d= -f2)"
echo "  ☐ Tamper detection: $(grep TAMPER_DETECTION_ENABLED "$INSTALL_DIR/.env" | cut -d= -f2)"
echo ""
echo "=========================================="
