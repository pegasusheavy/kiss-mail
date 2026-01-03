#!/bin/bash
# ============================================================================
# KISS Mail - One-Click Install Script
# ============================================================================
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/pegasusheavy/kiss-mail/main/deploy/scripts/install.sh | bash
#
# Or with options:
#   curl -fsSL ... | bash -s -- --domain mail.example.com --password mypass
# ============================================================================
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Defaults
DOMAIN="${KISS_MAIL_DOMAIN:-$(hostname -f)}"
ADMIN_PASSWORD=""
DATA_DIR="/opt/kiss-mail/data"
INSTALL_NGINX=true
INSTALL_CERTBOT=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -p|--password)
            ADMIN_PASSWORD="$2"
            shift 2
            ;;
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --no-nginx)
            INSTALL_NGINX=false
            shift
            ;;
        --no-certbot)
            INSTALL_CERTBOT=false
            shift
            ;;
        -h|--help)
            echo "KISS Mail Installer"
            echo ""
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -d, --domain DOMAIN    Mail domain (default: hostname)"
            echo "  -p, --password PASS    Admin password (default: auto-generated)"
            echo "  --data-dir DIR         Data directory (default: /opt/kiss-mail/data)"
            echo "  --no-nginx             Skip Nginx installation"
            echo "  --no-certbot           Skip Certbot installation"
            echo "  -h, --help             Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ----------------------------------------------------------------------------
# Functions
# ----------------------------------------------------------------------------
log() {
    echo -e "${GREEN}[KISS Mail]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

banner() {
    echo -e "${BLUE}"
    echo "  ╦╔═╦╔══╗  ╔╦╗╔═╗╦╦  "
    echo "  ╠╩╗║╚═╗╚═╗║║║╠═╣║║  "
    echo "  ╩ ╩╩╚═╝╚═╝╩ ╩╩ ╩╩╩═╝"
    echo -e "${NC}"
    echo "  Simple Email Server Installer"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        error "Cannot detect OS"
    fi
    log "Detected OS: $OS $VERSION"
}

install_docker() {
    if command -v docker &> /dev/null; then
        log "Docker already installed"
        return
    fi

    log "Installing Docker..."
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y ca-certificates curl gnupg
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            chmod a+r /etc/apt/keyrings/docker.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
            apt-get update
            apt-get install -y docker-ce docker-ce-cli containerd.io
            ;;
        centos|rhel|rocky|almalinux|fedora)
            dnf install -y dnf-plugins-core
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io
            ;;
        amzn)
            dnf install -y docker
            ;;
        *)
            error "Unsupported OS: $OS"
            ;;
    esac

    systemctl enable docker
    systemctl start docker
    log "Docker installed successfully"
}

install_nginx() {
    if [[ "$INSTALL_NGINX" != "true" ]]; then
        return
    fi

    if command -v nginx &> /dev/null; then
        log "Nginx already installed"
    else
        log "Installing Nginx..."
        case $OS in
            ubuntu|debian)
                apt-get install -y nginx
                ;;
            centos|rhel|rocky|almalinux|fedora|amzn)
                dnf install -y nginx
                ;;
        esac
    fi

    # Configure Nginx
    cat > /etc/nginx/conf.d/kiss-mail.conf << 'NGINX'
server {
    listen 80;
    server_name _;

    location /admin {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api {
        proxy_pass http://127.0.0.1:8025;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        return 301 /admin;
    }
}
NGINX

    # Remove default site on Debian/Ubuntu
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

    nginx -t && systemctl enable nginx && systemctl restart nginx
    log "Nginx configured successfully"
}

install_certbot() {
    if [[ "$INSTALL_CERTBOT" != "true" ]]; then
        return
    fi

    if command -v certbot &> /dev/null; then
        log "Certbot already installed"
        return
    fi

    log "Installing Certbot..."
    case $OS in
        ubuntu|debian)
            apt-get install -y certbot python3-certbot-nginx
            ;;
        centos|rhel|rocky|almalinux|fedora|amzn)
            dnf install -y certbot python3-certbot-nginx
            ;;
    esac
    log "Certbot installed (run 'certbot --nginx -d $DOMAIN' to enable HTTPS)"
}

setup_firewall() {
    log "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 22/tcp
        ufw allow 25/tcp
        ufw allow 587/tcp
        ufw allow 143/tcp
        ufw allow 110/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw --force enable || true
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-service=smtp
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --permanent --add-port=587/tcp
        firewall-cmd --permanent --add-port=143/tcp
        firewall-cmd --permanent --add-port=110/tcp
        firewall-cmd --reload || true
    fi
}

install_kiss_mail() {
    log "Installing KISS Mail..."

    # Create directories
    mkdir -p "$DATA_DIR"
    chown -R 1000:1000 "$(dirname "$DATA_DIR")"

    # Pull container image (preferred method)
    log "Pulling Docker image from registry..."
    if docker pull ghcr.io/pegasusheavy/kiss-mail:latest; then
        KISS_MAIL_IMAGE="ghcr.io/pegasusheavy/kiss-mail:latest"
        log "Using official container image"
    else
        warn "Registry image not available, building from source..."
        
        local tmpdir=$(mktemp -d)
        cd "$tmpdir"
        
        if command -v git &> /dev/null; then
            git clone --depth 1 https://github.com/pegasusheavy/kiss-mail.git .
        else
            curl -sL https://github.com/pegasusheavy/kiss-mail/archive/main.tar.gz | tar xz --strip-components=1
        fi
        
        docker build -t kiss-mail:latest .
        cd /
        rm -rf "$tmpdir"
        KISS_MAIL_IMAGE="kiss-mail:latest"
    fi

    # Generate API key
    API_KEY=$(openssl rand -hex 32)

    # Stop existing container
    docker stop kiss-mail 2>/dev/null || true
    docker rm kiss-mail 2>/dev/null || true

    # Run container
    log "Starting KISS Mail container..."
    docker run -d \
        --name kiss-mail \
        --restart unless-stopped \
        -p 25:2525 \
        -p 587:2525 \
        -p 143:1143 \
        -p 110:1100 \
        -p 8080:8080 \
        -p 8025:8025 \
        -v "$DATA_DIR":/data \
        -e KISS_MAIL_DOMAIN="$DOMAIN" \
        -e KISS_MAIL_API_KEY="$API_KEY" \
        -e KISS_MAIL_WEB_BIND=0.0.0.0 \
        -e KISS_MAIL_API_BIND=0.0.0.0 \
        -e RUST_LOG=info \
        "$KISS_MAIL_IMAGE"

    # Wait for startup
    log "Waiting for KISS Mail to start..."
    sleep 5

    # Create admin user
    if [[ -n "$ADMIN_PASSWORD" ]]; then
        docker exec kiss-mail kiss-mail add admin "$ADMIN_PASSWORD" --role superadmin || true
    fi

    # Save credentials
    PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "YOUR_IP")
    
    cat > /opt/kiss-mail/credentials.txt << EOF
KISS Mail Server Credentials
=============================
Domain: $DOMAIN
API Key: $API_KEY
Web Admin: http://$PUBLIC_IP/admin

Generated: $(date)
EOF

    chmod 600 /opt/kiss-mail/credentials.txt

    log "KISS Mail installed successfully"
}

print_summary() {
    PUBLIC_IP=$(curl -s ifconfig.me || curl -s icanhazip.com || echo "YOUR_IP")
    
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  KISS Mail Installation Complete!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  Web Admin:    http://$PUBLIC_IP/admin"
    echo "  SMTP:         $PUBLIC_IP:25"
    echo "  IMAP:         $PUBLIC_IP:143"
    echo "  POP3:         $PUBLIC_IP:110"
    echo ""
    echo "  Credentials:  /opt/kiss-mail/credentials.txt"
    echo ""
    echo -e "  ${YELLOW}DNS Records to configure:${NC}"
    echo ""
    echo "    A     $DOMAIN              $PUBLIC_IP"
    echo "    MX    $DOMAIN    10        $DOMAIN"
    echo "    TXT   $DOMAIN              \"v=spf1 ip4:$PUBLIC_IP -all\""
    echo ""
    echo -e "  ${YELLOW}To enable HTTPS:${NC}"
    echo "    certbot --nginx -d $DOMAIN"
    echo ""
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
    banner
    check_root
    detect_os
    
    log "Domain: $DOMAIN"
    log "Data directory: $DATA_DIR"
    echo ""

    install_docker
    install_nginx
    install_certbot
    setup_firewall
    install_kiss_mail
    
    print_summary
}

main "$@"
