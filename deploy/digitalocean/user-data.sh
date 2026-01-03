#!/bin/bash
# ============================================================================
# KISS Mail - Digital Ocean Droplet User Data Script
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
apt-get update
apt-get install -y nginx certbot python3-certbot-nginx ufw

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
    apt-get install -y git
    cd /tmp
    git clone https://github.com/pegasusheavy/kiss-mail.git
    cd kiss-mail
    docker build -t kiss-mail:latest .
}

# Generate API key
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
cat > /etc/nginx/sites-available/kiss-mail << 'NGINX'
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

# Enable site
ln -sf /etc/nginx/sites-available/kiss-mail /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and reload Nginx
nginx -t && systemctl enable nginx && systemctl restart nginx

# ----------------------------------------------------------------------------
# UFW Firewall
# ----------------------------------------------------------------------------
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 25/tcp    # SMTP
ufw allow 587/tcp   # SMTP Submission
ufw allow 143/tcp   # IMAP
ufw allow 110/tcp   # POP3
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw --force enable

# ----------------------------------------------------------------------------
# Save credentials
# ----------------------------------------------------------------------------
PUBLIC_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address)

cat > /opt/kiss-mail/credentials.txt << EOF
KISS Mail Server Credentials
=============================
Domain: $DOMAIN
API Key: $API_KEY
Web Admin: http://$PUBLIC_IP/admin

Generated: $(date)
EOF

chmod 600 /opt/kiss-mail/credentials.txt

# ----------------------------------------------------------------------------
# Setup Complete
# ----------------------------------------------------------------------------
echo "KISS Mail setup complete at $(date)"
echo "Web Admin: http://$PUBLIC_IP/admin"
echo "Credentials saved to /opt/kiss-mail/credentials.txt"
