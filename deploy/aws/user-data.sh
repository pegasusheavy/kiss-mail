#!/bin/bash
# ============================================================================
# KISS Mail - AWS EC2 User Data Script
# ============================================================================
set -euo pipefail

# Variables from Terraform
DOMAIN="${domain}"
ADMIN_PASSWORD="${admin_password}"

# Logging
exec > >(tee /var/log/kiss-mail-setup.log) 2>&1
echo "Starting KISS Mail setup at $(date)"

# ----------------------------------------------------------------------------
# System Setup
# ----------------------------------------------------------------------------
dnf update -y
dnf install -y docker nginx certbot python3-certbot-nginx

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Create kiss-mail user
useradd -r -s /bin/false kissmail || true

# Create data directory
mkdir -p /opt/kiss-mail/data
chown -R 1000:1000 /opt/kiss-mail

# ----------------------------------------------------------------------------
# Pull and Run KISS Mail
# ----------------------------------------------------------------------------
# Pull latest image (or build from source)
docker pull ghcr.io/pegasusheavy/kiss-mail:latest || {
    echo "Image not found, building from source..."
    dnf install -y git
    cd /tmp
    git clone https://github.com/pegasusheavy/kiss-mail.git
    cd kiss-mail
    docker build -t kiss-mail:latest .
}

# Generate API key if not provided
API_KEY=$(openssl rand -hex 32)

# Run container
docker run -d \
    --name kiss-mail \
    --restart unless-stopped \
    -p 25:2525 \
    -p 587:2525 \
    -p 143:1143 \
    -p 110:1100 \
    -p 8080:8080 \
    -p 8025:8025 \
    -v /opt/kiss-mail/data:/data \
    -e KISS_MAIL_DOMAIN="$DOMAIN" \
    -e KISS_MAIL_API_KEY="$API_KEY" \
    -e KISS_MAIL_WEB_BIND=0.0.0.0 \
    -e KISS_MAIL_API_BIND=0.0.0.0 \
    -e RUST_LOG=info \
    kiss-mail:latest || docker start kiss-mail

# Wait for server to start
sleep 10

# Create admin user if password provided
if [ -n "$ADMIN_PASSWORD" ]; then
    docker exec kiss-mail kiss-mail add admin "$ADMIN_PASSWORD" --role superadmin || true
fi

# ----------------------------------------------------------------------------
# Nginx Reverse Proxy
# ----------------------------------------------------------------------------
cat > /etc/nginx/conf.d/kiss-mail.conf << 'NGINX'
server {
    listen 80;
    server_name _;

    # Web Admin
    location /admin {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API
    location /api {
        proxy_pass http://127.0.0.1:8025;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Root redirect
    location / {
        return 301 /admin;
    }
}
NGINX

# Test and reload Nginx
nginx -t && systemctl enable nginx && systemctl restart nginx

# ----------------------------------------------------------------------------
# Firewall (if firewalld is available)
# ----------------------------------------------------------------------------
if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-service=smtp || true
    firewall-cmd --permanent --add-service=http || true
    firewall-cmd --permanent --add-service=https || true
    firewall-cmd --permanent --add-port=587/tcp || true
    firewall-cmd --permanent --add-port=143/tcp || true
    firewall-cmd --permanent --add-port=110/tcp || true
    firewall-cmd --reload || true
fi

# ----------------------------------------------------------------------------
# Save credentials
# ----------------------------------------------------------------------------
cat > /opt/kiss-mail/credentials.txt << EOF
KISS Mail Server Credentials
=============================
Domain: $DOMAIN
API Key: $API_KEY
Web Admin: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)/admin

Generated: $(date)
EOF

chmod 600 /opt/kiss-mail/credentials.txt

# ----------------------------------------------------------------------------
# Setup Complete
# ----------------------------------------------------------------------------
echo "KISS Mail setup complete at $(date)"
echo "Web Admin: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)/admin"
echo "Credentials saved to /opt/kiss-mail/credentials.txt"
