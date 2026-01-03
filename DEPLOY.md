# KISS Mail Deployment Guide

This guide covers all deployment options for KISS Mail.

> **Recommended**: All deployments use **Docker containers** from `ghcr.io/pegasusheavy/kiss-mail:latest`

## Deployment Options

| Method | Best For | Complexity | Cost |
|--------|----------|------------|------|
| [One-Click Script](#one-click-install) | Any VPS | ⭐ Easy | VPS cost |
| [Docker](#docker) | Local/Dev | ⭐ Easy | Free |
| [Docker Compose](#docker-compose) | Self-hosted | ⭐ Easy | VPS cost |
| [AWS Terraform](#aws) | Production | ⭐⭐ Medium | ~$10/mo |
| [GCP Terraform](#google-cloud-platform) | Production | ⭐⭐ Medium | ~$5-10/mo |
| [Azure Terraform](#microsoft-azure) | Production | ⭐⭐ Medium | ~$10-15/mo |
| [Digital Ocean Terraform](#digital-ocean) | Production | ⭐⭐ Medium | ~$6/mo |
| [Linode Terraform](#linode) | Production | ⭐⭐ Medium | ~$5/mo |
| [Vultr Terraform](#vultr) | Production | ⭐⭐ Medium | ~$5/mo |
| [Hetzner Terraform](#hetzner) | Production | ⭐⭐ Medium | ~€3/mo |
| [Generic Cloud-Init](#generic-any-cloud) | Any Cloud | ⭐ Easy | Variable |
| [Kubernetes](#kubernetes) | Enterprise | ⭐⭐⭐ Advanced | Variable |
| [Helm](#helm) | Enterprise | ⭐⭐⭐ Advanced | Variable |

---

## One-Click Install

The fastest way to deploy on any Linux server.

### Requirements
- Ubuntu 20.04+, Debian 11+, CentOS 8+, Rocky Linux, Amazon Linux 2023, or Fedora
- Root access
- Open ports: 22, 25, 80, 110, 143, 443, 587

### Install

```bash
curl -fsSL https://raw.githubusercontent.com/pegasusheavy/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

### Install with Options

```bash
curl -fsSL ... | sudo bash -s -- \
  --domain mail.example.com \
  --password your-admin-password
```

### Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Mail domain (default: hostname) |
| `-p, --password` | Admin password (default: auto-generated) |
| `--data-dir` | Data directory (default: /opt/kiss-mail/data) |
| `--no-nginx` | Skip Nginx installation |
| `--no-certbot` | Skip Certbot installation |

### Post-Install

1. View credentials: `cat /opt/kiss-mail/credentials.txt`
2. Access web admin: `http://YOUR_IP/admin`
3. Enable HTTPS: `sudo certbot --nginx -d mail.example.com`

---

## Docker

### Quick Start

```bash
docker run -d \
  --name kiss-mail \
  -p 25:2525 -p 143:1143 -p 110:1100 -p 8080:8080 \
  -v kiss-mail-data:/data \
  -e KISS_MAIL_DOMAIN=mail.example.com \
  kiss-mail:latest
```

### Build from Source

```bash
git clone https://github.com/pegasusheavy/kiss-mail.git
cd kiss-mail
docker build -t kiss-mail:latest .
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_DOMAIN` | hostname | Mail domain |
| `KISS_MAIL_DATA_DIR` | /data | Data directory |
| `KISS_MAIL_SMTP_PORT` | 2525 | SMTP port |
| `KISS_MAIL_IMAP_PORT` | 1143 | IMAP port |
| `KISS_MAIL_POP3_PORT` | 1100 | POP3 port |
| `KISS_MAIL_WEB_PORT` | 8080 | Web admin port |
| `KISS_MAIL_WEB_BIND` | 127.0.0.1 | Web bind address |
| `KISS_MAIL_API_PORT` | 8025 | API port |
| `KISS_MAIL_API_KEY` | - | API key for remote access |
| `RUST_LOG` | info | Log level |

---

## Docker Compose

### Basic Setup

```bash
cd deploy
docker-compose up -d
```

### With ClamAV Antivirus

```bash
docker-compose --profile antivirus up -d
```

### Environment File

Create `.env`:

```env
KISS_MAIL_DOMAIN=mail.example.com
KISS_MAIL_API_KEY=your-secret-key
```

### Commands

```bash
# Start
docker-compose up -d

# Stop
docker-compose down

# Logs
docker-compose logs -f kiss-mail

# Restart
docker-compose restart kiss-mail

# Update
docker-compose pull && docker-compose up -d
```

---

## AWS

Deploy on AWS with Terraform.

### Prerequisites

1. [Terraform](https://terraform.io) installed
2. [AWS CLI](https://aws.amazon.com/cli/) configured
3. AWS account with permissions

### Deploy

```bash
cd deploy/aws

# Configure
cp terraform.tfvars.example terraform.tfvars
vim terraform.tfvars

# Deploy
terraform init
terraform apply
```

### Configuration

Edit `terraform.tfvars`:

```hcl
region         = "us-east-1"
instance_type  = "t3.micro"      # Free tier eligible
domain         = "mail.example.com"
admin_password = "secure-password"
ssh_key_name   = "your-key"      # Optional
volume_size    = 20
```

### What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| VPC | Dedicated network | Free |
| EC2 | t3.micro instance | ~$8/mo (or free tier) |
| EIP | Static IP | Free (attached) |
| EBS | 20GB gp3 | ~$2/mo |
| Security Group | Firewall rules | Free |
| IAM Role | SSM access | Free |

### Access

```bash
# SSH (if key provided)
ssh -i ~/.ssh/key.pem ec2-user@<IP>

# SSM Session Manager (no key needed)
aws ssm start-session --target <instance-id>
```

### Cleanup

```bash
terraform destroy
```

---

## Digital Ocean

Deploy on Digital Ocean with Terraform.

### Prerequisites

1. [Terraform](https://terraform.io) installed
2. [Digital Ocean API token](https://cloud.digitalocean.com/account/api/tokens)

### Deploy

```bash
cd deploy/digitalocean

export DIGITALOCEAN_TOKEN="your-token"

terraform init
terraform apply -var="do_token=$DIGITALOCEAN_TOKEN"
```

### Configuration

Create `terraform.tfvars`:

```hcl
do_token       = "your-token"
region         = "nyc1"
droplet_size   = "s-1vcpu-1gb"   # $6/mo
domain         = "mail.example.com"
admin_password = "secure-password"
```

### Available Regions

| Region | Location |
|--------|----------|
| nyc1, nyc3 | New York |
| sfo3 | San Francisco |
| lon1 | London |
| ams3 | Amsterdam |
| sgp1 | Singapore |
| blr1 | Bangalore |
| fra1 | Frankfurt |
| tor1 | Toronto |
| syd1 | Sydney |

### What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| Droplet | s-1vcpu-1gb | $6/mo |
| Reserved IP | Static IP | Free |
| Firewall | Port rules | Free |
| Project | Organization | Free |

### Access

```bash
ssh root@<reserved-ip>
```

### Cleanup

```bash
terraform destroy -var="do_token=$DIGITALOCEAN_TOKEN"
```

---

## Google Cloud Platform

Deploy on GCP Compute Engine.

### Deploy

```bash
cd deploy/gcp

# Set project
gcloud config set project YOUR_PROJECT_ID

# Enable APIs
gcloud services enable compute.googleapis.com

# Deploy
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Resource | Cost |
|----------|------|
| e2-micro | Free tier eligible |
| Static IP | ~$3/month |

---

## Microsoft Azure

Deploy on Azure Virtual Machines.

### Deploy

```bash
cd deploy/azure

# Login
az login

# Deploy
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Size | Cost |
|------|------|
| Standard_B1s | ~$8/month |
| Standard_B1ms | ~$15/month |

---

## Linode

Deploy on Linode (Akamai).

### Deploy

```bash
cd deploy/linode
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Type | Cost |
|------|------|
| g6-nanode-1 (1GB) | $5/month |
| g6-standard-1 (2GB) | $10/month |

---

## Vultr

Deploy on Vultr.

### Deploy

```bash
cd deploy/vultr
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Plan | Cost |
|------|------|
| vc2-1c-1gb | $5/month |
| vc2-1c-2gb | $10/month |

---

## Hetzner

Deploy on Hetzner Cloud (EU-based, very affordable).

### Deploy

```bash
cd deploy/hetzner
cp terraform.tfvars.example terraform.tfvars
terraform init
terraform apply
```

### Cost

| Type | Cost |
|------|------|
| cx11 (2GB) | €3.29/month |
| cx21 (4GB) | €5.49/month |

---

## Generic (Any Cloud)

Use the universal cloud-init configuration on **any** cloud provider.

### Supported Providers

- AWS, GCP, Azure, Digital Ocean, Linode, Vultr, Hetzner
- OVH, Scaleway, Oracle Cloud, UpCloud, and more
- Any VPS provider with cloud-init support

### Deploy

1. Copy `deploy/generic/cloud-init.yml`
2. Customize the config section:

```yaml
write_files:
  - path: /etc/kiss-mail.conf
    content: |
      KISS_MAIL_DOMAIN=mail.yourdomain.com
      KISS_MAIL_ADMIN_PASSWORD=your-password
```

3. Create VM with Ubuntu 22.04 and paste as user-data
4. Wait 2-5 minutes for setup

### Manual (No Cloud-Init)

```bash
curl -fsSL https://raw.githubusercontent.com/pegasusheavy/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

---

## Kubernetes

Deploy on any Kubernetes cluster.

### Using Kustomize

```bash
# Deploy
kubectl apply -k deploy/kubernetes/

# Verify
kubectl get pods -n kiss-mail
kubectl get svc -n kiss-mail

# Port forward
kubectl port-forward svc/kiss-mail 8080:8080 -n kiss-mail
```

### Customize

Edit `deploy/kubernetes/kustomization.yaml`:

```yaml
# Change image
images:
  - name: kiss-mail
    newName: your-registry/kiss-mail
    newTag: v1.0.0
```

Edit `deploy/kubernetes/configmap.yaml` for configuration.

---

## Helm

Deploy with Helm for more flexibility.

### Install

```bash
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  --set domain=mail.example.com
```

### With Custom Values

Create `values-prod.yaml`:

```yaml
domain: mail.example.com

image:
  repository: your-registry/kiss-mail
  tag: v1.0.0

persistence:
  size: 50Gi
  storageClass: fast-ssd

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: mail.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: kiss-mail-tls
      hosts:
        - mail.example.com

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 1Gi
```

Install with values:

```bash
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  -f values-prod.yaml
```

### Upgrade

```bash
helm upgrade kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  -f values-prod.yaml
```

### Uninstall

```bash
helm uninstall kiss-mail --namespace kiss-mail
```

---

## DNS Configuration

After deployment, configure these DNS records:

| Type | Name | Value | Priority |
|------|------|-------|----------|
| A | mail.example.com | YOUR_IP | - |
| MX | example.com | mail.example.com | 10 |
| TXT | example.com | "v=spf1 ip4:YOUR_IP -all" | - |

### Optional: DKIM

Generate DKIM keys and add:

| Type | Name | Value |
|------|------|-------|
| TXT | mail._domainkey.example.com | "v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY" |

### Optional: DMARC

| Type | Name | Value |
|------|------|-------|
| TXT | _dmarc.example.com | "v=DMARC1; p=quarantine; rua=mailto:admin@example.com" |

---

## SSL/TLS

### With Certbot (Let's Encrypt)

```bash
sudo certbot --nginx -d mail.example.com
```

### With Custom Certificate

1. Place certificates in `/etc/ssl/kiss-mail/`
2. Update Nginx configuration

---

## Maintenance

### Upgrade

```bash
# Script
curl -fsSL .../upgrade.sh | sudo bash

# Docker
docker pull kiss-mail:latest
docker stop kiss-mail && docker rm kiss-mail
docker run ... kiss-mail:latest

# Helm
helm upgrade kiss-mail deploy/helm/kiss-mail ...
```

### Backup

```bash
# Data directory
tar -czvf kiss-mail-backup.tar.gz /opt/kiss-mail/data

# Docker volume
docker run --rm -v kiss-mail-data:/data -v $(pwd):/backup \
  alpine tar czvf /backup/kiss-mail-backup.tar.gz /data
```

### Logs

```bash
# Docker
docker logs kiss-mail

# Systemd (if installed as service)
journalctl -u kiss-mail

# Kubernetes
kubectl logs -f deployment/kiss-mail -n kiss-mail
```

---

## Troubleshooting

### Container won't start

```bash
# Check logs
docker logs kiss-mail

# Check ports
netstat -tlnp | grep -E '25|143|110|8080'
```

### Can't receive email

1. Check MX records: `dig MX example.com`
2. Check port 25 is open: `nc -vz YOUR_IP 25`
3. Check firewall rules
4. Check ISP isn't blocking port 25

### Web admin not accessible

```bash
# Check Nginx
nginx -t
systemctl status nginx

# Check container health
docker inspect kiss-mail --format '{{.State.Health.Status}}'
```

### SSL certificate issues

```bash
# Renew certificate
certbot renew

# Check certificate
openssl s_client -connect mail.example.com:443
```
