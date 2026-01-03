# ============================================================================
# KISS Mail - Vultr Terraform Configuration
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    vultr = {
      source  = "vultr/vultr"
      version = "~> 2.0"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "vultr_api_key" {
  description = "Vultr API key"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Vultr region"
  type        = string
  default     = "ewr"  # New Jersey
}

variable "plan" {
  description = "Vultr plan"
  type        = string
  default     = "vc2-1c-1gb"  # $5/month
}

variable "domain" {
  description = "Mail domain"
  type        = string
  default     = "mail.example.com"
}

variable "ssh_keys" {
  description = "SSH key IDs"
  type        = list(string)
  default     = []
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "vultr" {
  api_key = var.vultr_api_key
}

# ----------------------------------------------------------------------------
# Startup Script
# ----------------------------------------------------------------------------
resource "vultr_startup_script" "kiss_mail" {
  name   = "kiss-mail-setup"
  type   = "boot"
  script = base64encode(<<-EOF
    #!/bin/bash
    set -euo pipefail
    exec > >(tee /var/log/kiss-mail-setup.log) 2>&1
    
    # Install Docker
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker && systemctl start docker
    
    # Install extras
    apt-get update && apt-get install -y nginx certbot python3-certbot-nginx
    
    # Setup directories
    mkdir -p /opt/kiss-mail/data
    chown -R 1000:1000 /opt/kiss-mail
    
    # Generate API key
    API_KEY=$(openssl rand -hex 32)
    
    # Run KISS Mail
    docker run -d \
      --name kiss-mail \
      --restart unless-stopped \
      -p 25:2525 -p 587:2525 \
      -p 143:1143 -p 110:1100 \
      -p 8080:8080 -p 8025:8025 \
      -v /opt/kiss-mail/data:/data \
      -e KISS_MAIL_DOMAIN="${var.domain}" \
      -e KISS_MAIL_API_KEY="$API_KEY" \
      -e KISS_MAIL_WEB_BIND=0.0.0.0 \
      -e KISS_MAIL_API_BIND=0.0.0.0 \
      ghcr.io/pegasusheavy/kiss-mail:latest
    
    # Configure Nginx
    cat > /etc/nginx/sites-available/kiss-mail << 'NGINX'
    server {
        listen 80;
        server_name _;
        location /admin { proxy_pass http://127.0.0.1:8080; proxy_set_header Host $host; }
        location /api { proxy_pass http://127.0.0.1:8025; proxy_set_header Host $host; }
        location / { return 301 /admin; }
    }
    NGINX
    
    ln -sf /etc/nginx/sites-available/kiss-mail /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    systemctl restart nginx
    
    # Save credentials
    PUBLIC_IP=$(curl -s ifconfig.me)
    cat > /opt/kiss-mail/credentials.txt << CREDS
    KISS Mail Credentials
    Domain: ${var.domain}
    API Key: $API_KEY
    Web Admin: http://$PUBLIC_IP/admin
    CREDS
    chmod 600 /opt/kiss-mail/credentials.txt
  EOF
  )
}

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "vultr_firewall_group" "kiss_mail" {
  description = "KISS Mail Firewall"
}

resource "vultr_firewall_rule" "ssh" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "22"
}

resource "vultr_firewall_rule" "smtp" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "25"
}

resource "vultr_firewall_rule" "submission" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "587"
}

resource "vultr_firewall_rule" "imap" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "143"
}

resource "vultr_firewall_rule" "pop3" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "110"
}

resource "vultr_firewall_rule" "http" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "80"
}

resource "vultr_firewall_rule" "https" {
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  protocol          = "tcp"
  ip_type           = "v4"
  subnet            = "0.0.0.0"
  subnet_size       = 0
  port              = "443"
}

# ----------------------------------------------------------------------------
# Instance
# ----------------------------------------------------------------------------
resource "vultr_instance" "kiss_mail" {
  label             = "kiss-mail"
  region            = var.region
  plan              = var.plan
  os_id             = 1743  # Ubuntu 22.04 LTS
  script_id         = vultr_startup_script.kiss_mail.id
  firewall_group_id = vultr_firewall_group.kiss_mail.id
  ssh_key_ids       = var.ssh_keys
  enable_ipv6       = true
  
  tags = ["kiss-mail"]
}

# ----------------------------------------------------------------------------
# Reserved IP
# ----------------------------------------------------------------------------
resource "vultr_reserved_ip" "kiss_mail" {
  region      = var.region
  ip_type     = "v4"
  instance_id = vultr_instance.kiss_mail.id
  label       = "kiss-mail-ip"
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  value = vultr_reserved_ip.kiss_mail.subnet
}

output "web_admin_url" {
  value = "http://${vultr_reserved_ip.kiss_mail.subnet}/admin"
}

output "ssh_command" {
  value = "ssh root@${vultr_reserved_ip.kiss_mail.subnet}"
}
