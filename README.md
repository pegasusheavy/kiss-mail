# KISS Mail

A dead-simple email server. SMTP, IMAP, and POP3 in one container.

## Quick Start (Docker)

```bash
# Run with Docker (recommended)
docker run -d \
  --name kiss-mail \
  -p 25:2525 -p 587:2525 \
  -p 143:1143 -p 110:1100 \
  -p 8080:8080 \
  -v kiss-mail-data:/data \
  -e KISS_MAIL_DOMAIN=mail.example.com \
  ghcr.io/pegasusheavy/kiss-mail:latest

# Access web admin
open http://localhost:8080/admin
```

That's it. The server starts and creates an admin account automatically.

### One-Line Deploy (Any VPS)

```bash
curl -fsSL https://raw.githubusercontent.com/pegasusheavy/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

### Build from Source (Optional)

```bash
cargo build --release
./target/release/kiss-mail
```

## Usage

```bash
# Start the server
kiss-mail

# Create a user
kiss-mail add alice mysecretpassword

# List users
kiss-mail list

# Change a password
kiss-mail passwd alice newpassword

# Delete a user
kiss-mail del alice

# Show stats
kiss-mail stats
```

## Connect Your Email Client

| Setting  | Value                |
|----------|----------------------|
| Server   | localhost            |
| SMTP     | 2525 (or 25 as root) |
| IMAP     | 1143 (or 143 as root)|
| POP3     | 1100 (or 110 as root)|
| Username | your_username        |
| Password | your_password        |
| Security | None                 |

## Environment Variables

| Variable        | Default       | Description          |
|-----------------|---------------|----------------------|
| KISS_MAIL_DATA  | ./mail_data   | Data directory       |
| KISS_MAIL_DOMAIN| (hostname)    | Email domain         |
| SMTP_PORT       | 2525          | SMTP port            |
| IMAP_PORT       | 1143          | IMAP port            |
| POP3_PORT       | 1100          | POP3 port            |

## Docker (Recommended)

Docker is the **preferred deployment method** for KISS Mail.

### Security

Our containers are built on [Docker Hardened Images](https://www.docker.com/products/hardened-images/) (Alpine-based):
- **Zero known CVEs** - Continuously scanned and patched
- **Minimal attack surface** - Alpine Linux base (~5MB)
- **SBOM included** - Full software bill of materials
- **Non-root user** - Runs as unprivileged user
- **Cryptographically signed** - Verifiable authenticity

### Pull from Registry

```bash
# Pull the official hardened image
docker pull ghcr.io/pegasusheavy/kiss-mail:latest

# Run container
docker run -d \
  --name kiss-mail \
  --restart unless-stopped \
  -p 25:2525 -p 587:2525 \
  -p 143:1143 -p 110:1100 \
  -p 8080:8080 -p 8025:8025 \
  -v kiss-mail-data:/data \
  -e KISS_MAIL_DOMAIN=mail.example.com \
  -e KISS_MAIL_WEB_BIND=0.0.0.0 \
  ghcr.io/pegasusheavy/kiss-mail:latest

# Create admin user
docker exec kiss-mail kiss-mail add admin yourpassword --role superadmin

# View logs
docker logs -f kiss-mail
```

### Build Locally (Optional)

```bash
# Using Docker Hardened Images (requires Docker Hub login for dhi.io)
docker login dhi.io
docker build -t kiss-mail .

# Or using standard Alpine (no login required)
docker build -f Dockerfile.alpine -t kiss-mail .
```

### Docker Compose

```bash
# Start all services
docker-compose up -d

# With ClamAV antivirus
docker-compose --profile antivirus up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

### Container Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_DOMAIN` | localhost | Mail domain |
| `KISS_MAIL_DATA_DIR` | /data | Data directory |
| `KISS_MAIL_WEB_BIND` | 127.0.0.1 | Web admin bind address |
| `KISS_MAIL_API_BIND` | 127.0.0.1 | API bind address |
| `KISS_MAIL_API_KEY` | - | API key for remote access |
| `KISS_MAIL_ENCRYPTION` | true | Enable email encryption |

## Kubernetes

### Using Kustomize

```bash
# Deploy
kubectl apply -k deploy/kubernetes/

# Check status
kubectl get pods -n kiss-mail

# Port forward for local access
kubectl port-forward svc/kiss-mail 8080:8080 -n kiss-mail
```

### Using Helm

```bash
# Install
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  --set domain=mail.example.com

# With ingress
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  --set domain=mail.example.com \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=mail.example.com

# With external LoadBalancer
helm install kiss-mail deploy/helm/kiss-mail \
  --namespace kiss-mail \
  --create-namespace \
  --set externalService.enabled=true

# Upgrade
helm upgrade kiss-mail deploy/helm/kiss-mail --namespace kiss-mail

# Uninstall
helm uninstall kiss-mail --namespace kiss-mail
```

## Cloud Deployment

All cloud deployments use **Docker containers** pulled from `ghcr.io/pegasusheavy/kiss-mail:latest`.

### One-Click Install (Any VPS)

SSH into your server and run:

```bash
curl -fsSL https://raw.githubusercontent.com/pegasusheavy/kiss-mail/main/deploy/scripts/install.sh | sudo bash
```

This installs Docker, pulls the container image, and starts KISS Mail automatically.

Works on Ubuntu, Debian, CentOS, Rocky Linux, Amazon Linux, Fedora, and more.

### Cloud Provider Comparison

All providers deploy the same Docker container:

| Provider | Cost | Deploy Command |
|----------|------|----------------|
| **Hetzner** | €3/mo | `cd deploy/hetzner && terraform apply` |
| **Vultr** | $5/mo | `cd deploy/vultr && terraform apply` |
| **Linode** | $5/mo | `cd deploy/linode && terraform apply` |
| **Digital Ocean** | $6/mo | `cd deploy/digitalocean && terraform apply` |
| **AWS** | $6-10/mo | `cd deploy/aws && terraform apply` |
| **GCP** | $5-10/mo | `cd deploy/gcp && terraform apply` |
| **Azure** | $10-15/mo | `cd deploy/azure && terraform apply` |
| **Any Cloud** | Variable | Use `deploy/generic/cloud-init.yml` |

### Quick Deploy (Terraform)

```bash
# Choose your provider
cd deploy/aws          # or gcp, azure, digitalocean, linode, vultr, hetzner

# Configure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

# Deploy (pulls Docker container automatically)
terraform init
terraform apply
```

### Generic Cloud-Init

For any cloud provider (OVH, Scaleway, Oracle, UpCloud, etc.):

1. Copy `deploy/generic/cloud-init.yml`
2. Edit the config section with your domain
3. Create VM with Ubuntu 22.04 and paste as user-data
4. Wait 2-5 minutes (installs Docker and pulls container)

### What Gets Deployed

All deployment methods create the same setup:
- Docker installed and configured
- KISS Mail container running with auto-restart
- Nginx reverse proxy for web admin
- Firewall rules for mail ports
- Data persisted in `/opt/kiss-mail/data`

### DNS Configuration

After deploying, configure these DNS records:

```
A     mail.yourdomain.com         YOUR_SERVER_IP
MX    yourdomain.com       10     mail.yourdomain.com
TXT   yourdomain.com              "v=spf1 ip4:YOUR_SERVER_IP -all"
```

### Enable HTTPS

SSH into your server and run:

```bash
sudo certbot --nginx -d mail.yourdomain.com
```

### Upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/pegasusheavy/kiss-mail/main/deploy/scripts/upgrade.sh | sudo bash
```

### Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/pegasusheavy/kiss-mail/main/deploy/scripts/uninstall.sh | sudo bash

# Keep data
curl -fsSL ... | sudo bash -s -- --keep-data
```

## Features

- ✅ SMTP server (send/receive)
- ✅ IMAP server (read emails)
- ✅ POP3 server (download emails)
- ✅ **Zero-Knowledge Encryption** (ProtonMail-style)
- ✅ **Web Admin Dashboard** (Tailwind CSS)
- ✅ Remote CLI & REST API
- ✅ SSO authentication (1Password, Google, Microsoft, Okta, Auth0)
- ✅ LDAP authentication (Active Directory, OpenLDAP)
- ✅ Groups / distribution lists
- ✅ AI spam detection (Bayesian classifier + rules)
- ✅ Anti-virus scanning (built-in + ClamAV)
- ✅ User management
- ✅ Zero configuration
- ✅ Single binary

## Email Encryption

KISS Mail automatically encrypts emails at rest using ProtonMail-style zero-knowledge encryption.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Registration                           │
│  Password → Argon2 → Key Encryption Key (KEK)                  │
│  Generate X25519 keypair                                        │
│  Private key encrypted with KEK → stored                        │
│  Public key → stored (unencrypted)                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     Email Encryption                            │
│  1. Generate random symmetric key (per email)                   │
│  2. Encrypt email body with ChaCha20-Poly1305                   │
│  3. Encrypt symmetric key with recipient's public key           │
│  4. Store: encrypted_key + nonce + ciphertext                   │
└─────────────────────────────────────────────────────────────────┘
```

### Security Properties

| Property | Description |
|----------|-------------|
| **Zero-Knowledge** | Server cannot read your emails |
| **Per-User Keys** | X25519 key pair for each user |
| **Password-Protected** | Private key encrypted with Argon2 |
| **Per-Email Keys** | Unique symmetric key per email |
| **Modern Crypto** | ChaCha20-Poly1305 authenticated encryption |

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_ENCRYPTION` | true | Enable/disable encryption |

### Startup Banner

```
Security:
  Anti-spam   ✓ Rules + AI (1234 patterns learned)
  Anti-virus  ✓ Built-in
  Encryption  ✓ X25519-ChaCha20-Poly1305 (5 keys)
```

### Key Management

- Keys are automatically generated when a user is created
- Private keys are encrypted with the user's password
- Password changes re-encrypt the private key
- Keys are stored in `keys.json` in the data directory

## AI Spam Detection

KISS Mail uses a hybrid spam detection system:

### How It Works

1. **Bayesian Classifier** - Self-learning AI that:
   - Learns from spam/ham patterns
   - Extracts 50+ features (URLs, caps, urgency words, etc.)
   - Persists learned data to disk
   - Seeds with common spam patterns on first run

2. **Rule-based Scoring** - Traditional heuristics:
   - Rate limiting
   - Keyword detection
   - Header analysis
   - Suspicious URL patterns

3. **Combined Decision** - Weighted average of AI + rules (60%/40% default)

### What You'll See

```
Security:
  Anti-spam   ✓ Rules + AI (847 patterns learned)
  Anti-virus  ✓ ClamAV 1.0.0
```

### Self-Learning

The classifier improves over time as it sees more emails. Patterns are saved to `mail_data/spam_classifier.json`.

## Groups / Distribution Lists

Create email groups to send messages to multiple users at once.

### Quick Start

```bash
# Create a group (auto-generates email: developers@yourdomain.com)
kiss-mail group-add developers

# Or specify a custom email
kiss-mail group-add team team-all@example.com

# Add members
kiss-mail group-add-member developers alice
kiss-mail group-add-member developers bob

# List groups
kiss-mail groups

# View group details
kiss-mail group-info developers
```

### How It Works

When an email is sent to a group address (e.g., `developers@yourdomain.com`), it's automatically expanded and delivered to all group members.

### Group Features

| Feature | Description |
|---------|-------------|
| **Distribution lists** | Emails to group go to all members |
| **Visibility levels** | Public, Internal, Private, Hidden |
| **Roles** | Owner, Manager, Member |
| **Settings** | External senders, moderation, reply-to |

### CLI Commands

```bash
groups                           # List all groups
group-add <name> [email]         # Create group
group-del <name>                 # Delete group
group-info <name>                # Show details
group-add-member <group> <user>  # Add user
group-rm-member <group> <user>   # Remove user
```

### Data Storage

Groups are persisted to `mail_data/groups.json`.

## LDAP Integration

Authenticate users against LDAP directories (Active Directory, OpenLDAP, etc.).

### Quick Setup

```bash
# Set LDAP server URL to enable
export LDAP_URL=ldap://ldap.example.com:389
export LDAP_BASE_DN=dc=example,dc=com

# Optional: Service account for user searches
export LDAP_BIND_DN=cn=admin,dc=example,dc=com
export LDAP_BIND_PASSWORD=secret

# Start server
kiss-mail
```

### Test LDAP Connection

```bash
# Test connection
kiss-mail ldap-test

# Test authentication
kiss-mail ldap-auth username password

# Search for user
kiss-mail ldap-search username
```

### Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `LDAP_URL` | LDAP server URL | (disabled) |
| `LDAP_BASE_DN` | Base DN for searches | `dc=example,dc=com` |
| `LDAP_BIND_DN` | Service account DN | (anonymous) |
| `LDAP_BIND_PASSWORD` | Service account password | (none) |
| `LDAP_USER_FILTER` | User search filter | `(&(objectClass=inetOrgPerson)(uid={username}))` |
| `LDAP_USER_DN_TEMPLATE` | User DN template | `uid={username},ou=users,dc=example,dc=com` |
| `LDAP_USE_TLS` | Use TLS (ldaps://) | `false` |
| `LDAP_FALLBACK_LOCAL` | Fall back to local auth | `true` |

### Active Directory Example

```bash
export LDAP_URL=ldap://dc.example.com:389
export LDAP_BASE_DN=dc=example,dc=com
export LDAP_BIND_DN=cn=service,cn=users,dc=example,dc=com
export LDAP_BIND_PASSWORD=secret
export LDAP_USER_FILTER="(&(objectClass=user)(sAMAccountName={username}))"
export LDAP_USER_DN_TEMPLATE="{username}@example.com"
```

### How It Works

1. User attempts to login via IMAP/POP3
2. If LDAP is configured, authenticate against LDAP first
3. On success, auto-create local mailbox if needed
4. If LDAP fails and fallback is enabled, try local auth
5. Local mailboxes store emails, LDAP provides authentication

### Startup Banner

```
Directory:
  LDAP        ✓ ldap://ldap.example.com:389 (TLS)
```

## SSO Integration

Authenticate users via Single Sign-On providers using OAuth2/OIDC.

### Supported Providers

| Provider | Setup |
|----------|-------|
| **1Password** | `ONEPASSWORD_CLIENT_ID`, `ONEPASSWORD_CLIENT_SECRET` |
| **Google** | `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` |
| **Microsoft** | `MICROSOFT_CLIENT_ID`, `MICROSOFT_CLIENT_SECRET`, `MICROSOFT_TENANT_ID` |
| **Okta** | `OKTA_CLIENT_ID`, `OKTA_CLIENT_SECRET`, `OKTA_DOMAIN` |
| **Auth0** | `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_DOMAIN` |
| **Generic OIDC** | `SSO_CLIENT_ID`, `SSO_CLIENT_SECRET`, `SSO_AUTH_URL`, `SSO_TOKEN_URL` |

### Quick Setup (Google Example)

```bash
export GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=your-client-secret
kiss-mail
```

### App Passwords

Since email clients (Thunderbird, Outlook, etc.) don't support OAuth2, generate **app passwords**:

```bash
# Generate app password for a user
kiss-mail app-password alice "Thunderbird"
# Output: abcd-efgh-jkmn-pqrs-tuvw-xyz1

# List app passwords
kiss-mail app-passwords alice

# Revoke app password
kiss-mail app-pass-revoke alice <password-id>
```

Use the generated password in your mail client instead of your SSO password.

### CLI Commands

```bash
kiss-mail sso-status                    # Show SSO configuration
kiss-mail app-password <user> [label]   # Generate app password
kiss-mail app-passwords <user>          # List app passwords  
kiss-mail app-pass-revoke <user> <id>   # Revoke app password
```

### Startup Banner

```
Identity:
  LDAP        ✓ ldap://ldap.example.com:389
  SSO         ✓ Google + app passwords
```

## Web Admin Dashboard

A simple, beautiful web interface for managing your mail server.

### Access

```
http://localhost:8080/admin
```

Login with any admin user credentials.

### Features

- **Dashboard** - Server overview, stats, quick actions
- **Users** - Create, edit, delete users; manage roles and status
- **Groups** - Create distribution lists, manage members

### Screenshots

The interface uses Tailwind CSS for a clean, modern design:

- Clean navigation with active state highlighting
- Responsive tables for users and groups
- Form validation and flash messages
- Session-based authentication

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_WEB_ENABLED` | true | Enable web admin |
| `KISS_MAIL_WEB_PORT` | 8080 | Web admin port |
| `KISS_MAIL_WEB_BIND` | 127.0.0.1 | Bind address |

### Startup Banner

```
Servers:
  SMTP  →  localhost:2525
  IMAP  →  localhost:1143
  POP3  →  localhost:1100
  Web   →  http://localhost:8080/admin
```

## Remote Administration

Manage the server remotely via CLI or REST API.

### Enable Remote API

Set an API key to enable remote access:

```bash
export KISS_MAIL_API_KEY=your-secret-key
kiss-mail
```

The API server starts on port 8025 by default:

```
Servers:
  SMTP  →  localhost:2525
  IMAP  →  localhost:1143
  POP3  →  localhost:1100
  API   →  localhost:8025
```

### Remote CLI Usage

```bash
# Using flags
kiss-mail --server mail.example.com:8025 --api-key your-secret-key list

# Short flags
kiss-mail -s localhost:8025 -k mykey status

# Using environment variables  
export KISS_MAIL_SERVER=mail.example.com:8025
export KISS_MAIL_API_KEY=your-secret-key
kiss-mail list
kiss-mail add bob password123
kiss-mail group-add developers
```

### Supported Remote Commands

| Command | Description |
|---------|-------------|
| `status` | Show server status |
| `list` | List all users |
| `add <user> <pass>` | Create user |
| `del <user>` | Delete user |
| `info <user>` | Show user details |
| `groups` | List all groups |
| `group-add <name>` | Create group |
| `group-del <name>` | Delete group |
| `group-add-member <grp> <usr>` | Add user to group |
| `group-rm-member <grp> <usr>` | Remove user from group |
| `ldap-test` | Test LDAP connection |

### REST API Endpoints

The admin API also provides REST endpoints for programmatic access:

```bash
# Authentication
POST /api/auth/login     # Login with admin credentials
POST /api/auth/logout    # Logout

# Status
GET  /api/status         # Server status

# Users
GET  /api/users          # List users
POST /api/users          # Create user
GET  /api/users/:user    # Get user
PUT  /api/users/:user    # Update user
DELETE /api/users/:user  # Delete user

# Groups
GET  /api/groups         # List groups
POST /api/groups         # Create group
GET  /api/groups/:name   # Get group
DELETE /api/groups/:name # Delete group
POST /api/groups/:name/members           # Add member
DELETE /api/groups/:name/members/:user   # Remove member

# App Passwords
GET  /api/users/:user/app-passwords      # List app passwords
POST /api/users/:user/app-passwords      # Generate app password
DELETE /api/users/:user/app-passwords/:id # Revoke app password

# LDAP
GET  /api/ldap/status    # LDAP status
POST /api/ldap/test      # Test LDAP connection

# SSO  
GET  /api/sso/status     # SSO status
```

### Example API Calls

```bash
# Get status
curl -H "Authorization: Bearer your-api-key" http://localhost:8025/api/status

# Create user
curl -X POST -H "Authorization: Bearer your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}' \
  http://localhost:8025/api/users

# List groups
curl -H "X-API-Key: your-api-key" http://localhost:8025/api/groups
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `KISS_MAIL_API_KEY` | - | API key (enables API if set) |
| `KISS_MAIL_API_PORT` | 8025 | API server port |
| `KISS_MAIL_API_BIND` | 127.0.0.1 | Bind address |
| `KISS_MAIL_API_ENABLED` | false | Enable API without key |

## ClamAV Integration

KISS Mail automatically detects and uses ClamAV if available. No configuration needed!

### Install ClamAV (optional)

```bash
# Debian/Ubuntu
sudo apt install clamav-daemon
sudo systemctl start clamav-daemon

# macOS
brew install clamav
clamd

# The server will auto-detect ClamAV at 127.0.0.1:3310
```

### Configure ClamAV

| Variable | Default | Description |
|----------|---------|-------------|
| CLAMAV_ADDRESS | 127.0.0.1:3310 | ClamAV daemon address |
| CLAMAV_ENABLED | true | Enable ClamAV scanning |

```bash
# Use custom ClamAV address
CLAMAV_ADDRESS=192.168.1.100:3310 kiss-mail

# Disable ClamAV (use built-in only)
CLAMAV_ENABLED=false kiss-mail
```

When ClamAV is available, you'll see:
```
Security:
  Anti-spam   ✓ Enabled
  Anti-virus  ✓ ClamAV 1.0.0/26789/...
```

When ClamAV is not available, the built-in scanner is used:
```
Security:
  Anti-spam   ✓ Enabled
  Anti-virus  ✓ Built-in (ClamAV not found)
```

## License

MIT
