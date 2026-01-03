# ============================================================================
# KISS Mail - Hetzner Cloud Terraform Configuration
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "location" {
  description = "Hetzner location"
  type        = string
  default     = "nbg1"  # Nuremberg
}

variable "server_type" {
  description = "Server type"
  type        = string
  default     = "cx11"  # €3.29/month
}

variable "domain" {
  description = "Mail domain"
  type        = string
  default     = "mail.example.com"
}

variable "ssh_keys" {
  description = "SSH key names"
  type        = list(string)
  default     = []
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "hcloud" {
  token = var.hcloud_token
}

# ----------------------------------------------------------------------------
# SSH Key (optional)
# ----------------------------------------------------------------------------
# resource "hcloud_ssh_key" "default" {
#   name       = "kiss-mail"
#   public_key = file("~/.ssh/id_rsa.pub")
# }

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "hcloud_firewall" "kiss_mail" {
  name = "kiss-mail-firewall"

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "25"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "587"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "143"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "110"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    protocol  = "icmp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

# ----------------------------------------------------------------------------
# Server
# ----------------------------------------------------------------------------
resource "hcloud_server" "kiss_mail" {
  name        = "kiss-mail"
  image       = "docker-ce"
  server_type = var.server_type
  location    = var.location
  ssh_keys    = var.ssh_keys
  
  firewall_ids = [hcloud_firewall.kiss_mail.id]

  user_data = <<-EOF
    #cloud-config
    package_update: true
    packages:
      - nginx
      - certbot
      - python3-certbot-nginx

    runcmd:
      - mkdir -p /opt/kiss-mail/data
      - chown -R 1000:1000 /opt/kiss-mail
      - export API_KEY=$(openssl rand -hex 32)
      - |
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
      - |
        cat > /etc/nginx/sites-available/kiss-mail << 'NGINX'
        server {
            listen 80;
            server_name _;
            location /admin { proxy_pass http://127.0.0.1:8080; proxy_set_header Host $host; }
            location /api { proxy_pass http://127.0.0.1:8025; proxy_set_header Host $host; }
            location / { return 301 /admin; }
        }
        NGINX
      - ln -sf /etc/nginx/sites-available/kiss-mail /etc/nginx/sites-enabled/
      - rm -f /etc/nginx/sites-enabled/default
      - systemctl restart nginx
      - |
        PUBLIC_IP=$(curl -s ifconfig.me)
        cat > /opt/kiss-mail/credentials.txt << CREDS
        KISS Mail Credentials
        Domain: ${var.domain}
        API Key: $API_KEY
        Web Admin: http://$PUBLIC_IP/admin
        CREDS
      - chmod 600 /opt/kiss-mail/credentials.txt
  EOF

  labels = {
    app     = "kiss-mail"
    managed = "terraform"
  }
}

# ----------------------------------------------------------------------------
# Primary IP (Static)
# ----------------------------------------------------------------------------
resource "hcloud_primary_ip" "kiss_mail" {
  name          = "kiss-mail-ip"
  datacenter    = "${var.location}-dc2"
  type          = "ipv4"
  assignee_type = "server"
  assignee_id   = hcloud_server.kiss_mail.id
  auto_delete   = false
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  value = hcloud_server.kiss_mail.ipv4_address
}

output "web_admin_url" {
  value = "http://${hcloud_server.kiss_mail.ipv4_address}/admin"
}

output "ssh_command" {
  value = "ssh root@${hcloud_server.kiss_mail.ipv4_address}"
}
