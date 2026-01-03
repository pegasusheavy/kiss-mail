# KISS Mail - Universal Cloud Deployment

Deploy KISS Mail on **any cloud provider** using cloud-init.

## Supported Providers

This cloud-init configuration works on any provider that supports cloud-init:

| Provider | Instructions |
|----------|--------------|
| **AWS** | Use as EC2 User Data |
| **GCP** | Use as Startup Script |
| **Azure** | Use as Custom Data |
| **Digital Ocean** | Use as User Data |
| **Linode** | Use as StackScript or cloud-init |
| **Vultr** | Use as Startup Script |
| **Hetzner** | Use as User Data |
| **OVH** | Use as cloud-init |
| **Scaleway** | Use as cloud-init |
| **Oracle Cloud** | Use as cloud-init |
| **Any VPS** | Copy and run setup script |

## Quick Start

### Option 1: Cloud-Init (Recommended)

1. **Copy `cloud-init.yml`** and customize the config section at the top:

```yaml
write_files:
  - path: /etc/kiss-mail.conf
    content: |
      KISS_MAIL_DOMAIN=mail.yourdomain.com
      KISS_MAIL_ADMIN_PASSWORD=your-secure-password
      KISS_MAIL_API_KEY=
```

2. **Create a VM** with Ubuntu 22.04 or Debian 12 and paste the cloud-init as user-data

3. **Wait** for setup to complete (2-5 minutes)

4. **Access** web admin at `http://YOUR_IP/admin`

### Option 2: Manual Script

If your provider doesn't support cloud-init, SSH into any Linux server and run:

```bash
curl -fsSL https://raw.githubusercontent.com/pegasusheavy/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

## Configuration

Edit `/etc/kiss-mail.conf` before running:

| Variable | Description | Default |
|----------|-------------|---------|
| `KISS_MAIL_DOMAIN` | Your mail domain | mail.example.com |
| `KISS_MAIL_ADMIN_PASSWORD` | Initial admin password | (none) |
| `KISS_MAIL_API_KEY` | API key for remote access | (auto-generated) |

## Post-Deployment

### View Credentials

```bash
cat /opt/kiss-mail/credentials.txt
```

### Enable HTTPS

```bash
sudo certbot --nginx -d mail.yourdomain.com
```

### Configure DNS

Add these records:

```
A     mail.yourdomain.com         YOUR_SERVER_IP
MX    yourdomain.com       10     mail.yourdomain.com
TXT   yourdomain.com              "v=spf1 ip4:YOUR_SERVER_IP -all"
```

### View Logs

```bash
# Setup log
cat /var/log/kiss-mail-setup.log

# Container log
docker logs kiss-mail
```

## Minimum Requirements

- **OS**: Ubuntu 20.04+, Debian 11+, CentOS 8+, or any Linux with Docker
- **RAM**: 512MB minimum, 1GB recommended
- **Disk**: 10GB minimum
- **Ports**: 22, 25, 80, 110, 143, 443, 587

## Troubleshooting

### Container not running

```bash
docker ps -a
docker logs kiss-mail
docker start kiss-mail
```

### Nginx not working

```bash
nginx -t
systemctl status nginx
cat /var/log/nginx/error.log
```

### Can't receive email

1. Check MX records: `dig MX yourdomain.com`
2. Check port 25 is open
3. Check if ISP blocks port 25 (common on residential connections)
