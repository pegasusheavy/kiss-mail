# ============================================================================
# KISS Mail - Linode (Akamai) Terraform Configuration
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    linode = {
      source  = "linode/linode"
      version = "~> 2.0"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "linode_token" {
  description = "Linode API token"
  type        = string
  sensitive   = true
}

variable "region" {
  description = "Linode region"
  type        = string
  default     = "us-east"
}

variable "type" {
  description = "Linode instance type"
  type        = string
  default     = "g6-nanode-1"  # $5/month
}

variable "domain" {
  description = "Mail domain"
  type        = string
  default     = "mail.example.com"
}

variable "root_password" {
  description = "Root password for Linode"
  type        = string
  sensitive   = true
}

variable "ssh_keys" {
  description = "SSH public keys"
  type        = list(string)
  default     = []
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "linode" {
  token = var.linode_token
}

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "linode_firewall" "kiss_mail" {
  label = "kiss-mail-firewall"

  inbound {
    label    = "allow-ssh"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "22"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-smtp"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "25"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-submission"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "587"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-imap"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "143"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-pop3"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "110"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-http"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "80"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound {
    label    = "allow-https"
    action   = "ACCEPT"
    protocol = "TCP"
    ports    = "443"
    ipv4     = ["0.0.0.0/0"]
    ipv6     = ["::/0"]
  }

  inbound_policy  = "DROP"
  outbound_policy = "ACCEPT"

  linodes = [linode_instance.kiss_mail.id]
}

# ----------------------------------------------------------------------------
# Linode Instance
# ----------------------------------------------------------------------------
resource "linode_instance" "kiss_mail" {
  label           = "kiss-mail"
  image           = "linode/docker-22.04"
  region          = var.region
  type            = var.type
  root_pass       = var.root_password
  authorized_keys = var.ssh_keys
  
  stackscript_id = linode_stackscript.kiss_mail.id
  stackscript_data = {
    domain = var.domain
  }

  tags = ["kiss-mail", "mail-server"]
}

# ----------------------------------------------------------------------------
# StackScript (cloud-init equivalent)
# ----------------------------------------------------------------------------
resource "linode_stackscript" "kiss_mail" {
  label       = "kiss-mail-setup"
  description = "KISS Mail Server Setup"
  script      = <<-EOF
    #!/bin/bash
    # <UDF name="domain" label="Mail Domain" default="mail.example.com" />
    
    set -euo pipefail
    exec > >(tee /var/log/kiss-mail-setup.log) 2>&1
    
    # Update system
    apt-get update && apt-get upgrade -y
    apt-get install -y nginx certbot python3-certbot-nginx
    
    # Create directories
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
      -e KISS_MAIL_DOMAIN="$DOMAIN" \
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
    Domain: $DOMAIN
    API Key: $API_KEY
    Web Admin: http://$PUBLIC_IP/admin
    CREDS
    chmod 600 /opt/kiss-mail/credentials.txt
    
    echo "KISS Mail setup complete!"
  EOF
  images      = ["linode/docker-22.04"]
  rev_note    = "Initial version"
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  value = linode_instance.kiss_mail.ip_address
}

output "web_admin_url" {
  value = "http://${linode_instance.kiss_mail.ip_address}/admin"
}

output "ssh_command" {
  value = "ssh root@${linode_instance.kiss_mail.ip_address}"
}
