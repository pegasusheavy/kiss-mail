# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of KISS Mail seriously. If you discover a security vulnerability, please follow responsible disclosure practices.

### For Critical Vulnerabilities

**DO NOT** open a public GitHub issue for critical security vulnerabilities.

Instead, please report them privately using one of these methods:

1. **GitHub Security Advisories** (Preferred):
   - Go to the [Security tab](https://github.com/pegasusheavy/kiss-mail/security/advisories)
   - Click "New draft security advisory"
   - Fill in the details

2. **Email**:
   - Send details to: `security@pegasusheavy.com`
   - Use PGP encryption if possible (key below)

### What to Include

Please include the following in your report:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential security impact
- **Affected versions**: Which versions are affected
- **Steps to reproduce**: Detailed reproduction steps
- **Proof of concept**: Code or commands to demonstrate (if possible)
- **Suggested fix**: Your recommendations (if any)

### PGP Key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
[Public key would be added here]
-----END PGP PUBLIC KEY BLOCK-----
```

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Initial response | 24-48 hours |
| Vulnerability confirmation | 1 week |
| Fix development | 1-4 weeks |
| Security advisory publication | After fix is released |

### What to Expect

1. **Acknowledgment**: We'll acknowledge your report within 48 hours
2. **Investigation**: We'll investigate and keep you updated
3. **Fix**: We'll develop and test a fix
4. **Release**: We'll release the fix and publish an advisory
5. **Credit**: We'll credit you (unless you prefer anonymity)

## Security Best Practices

When deploying KISS Mail, follow these security recommendations:

### Server Hardening

```bash
# Run as non-root user
sudo useradd -r -s /bin/false kissmail
sudo -u kissmail kiss-mail

# Use firewall
sudo ufw allow 25/tcp    # SMTP
sudo ufw allow 587/tcp   # Submission
sudo ufw allow 143/tcp   # IMAP
sudo ufw allow 110/tcp   # POP3
sudo ufw enable

# Enable TLS with Let's Encrypt
sudo certbot --nginx -d mail.example.com
```

### Environment Variables

```bash
# Enable encryption
export KISS_MAIL_ENCRYPTION=true

# Set strong API key
export KISS_MAIL_API_KEY=$(openssl rand -hex 32)

# Restrict bind addresses for admin interfaces
export KISS_MAIL_WEB_BIND=127.0.0.1
export KISS_MAIL_API_BIND=127.0.0.1
```

### Docker Security

```yaml
# Use read-only root filesystem
security_opt:
  - no-new-privileges:true
read_only: true

# Run as non-root
user: "1000:1000"

# Limit capabilities
cap_drop:
  - ALL
```

### Kubernetes Security

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

## Security Features

KISS Mail includes several security features:

### Email Encryption

- **Algorithm**: X25519 key exchange + ChaCha20-Poly1305
- **Key Protection**: Private keys encrypted with Argon2id
- **Per-Email Keys**: Unique symmetric key per email

### Password Security

- **Hashing**: Argon2id with secure parameters
- **Account Locking**: After failed login attempts
- **Password Requirements**: Configurable complexity

### Anti-Spam

- **Rule-based filtering**: Known spam patterns
- **Bayesian classifier**: AI-powered spam detection
- **Rate limiting**: Prevent abuse

### Anti-Virus

- **Built-in scanner**: EICAR and malware signatures
- **ClamAV integration**: Enterprise-grade scanning
- **Attachment filtering**: Block dangerous file types

## Known Security Considerations

### Current Limitations

1. **No TLS by default**: Use a reverse proxy (nginx) for TLS termination
2. **In-memory sessions**: Session data is lost on restart
3. **Single-node**: No built-in clustering (use external load balancer)

### Roadmap

- [ ] Native TLS support
- [ ] DKIM signing
- [ ] SPF validation
- [ ] DMARC support
- [ ] Rate limiting improvements

## Security Updates

Security updates are announced via:

- [GitHub Security Advisories](https://github.com/pegasusheavy/kiss-mail/security/advisories)
- [GitHub Releases](https://github.com/pegasusheavy/kiss-mail/releases)

Subscribe to releases to stay informed about security patches.

## Acknowledgments

We thank the following security researchers for responsibly disclosing vulnerabilities:

- *No reported vulnerabilities yet*

---

Thank you for helping keep KISS Mail and its users safe! 🔒
