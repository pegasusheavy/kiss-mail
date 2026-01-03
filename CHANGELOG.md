# Changelog

All notable changes to KISS Mail will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Zero-knowledge email encryption (ProtonMail-style)
  - X25519 key exchange
  - ChaCha20-Poly1305 authenticated encryption
  - Password-protected private keys with Argon2id
- Web admin dashboard with Tailwind CSS
- REST API for remote administration
- Remote CLI support (`--server` and `--api-key` flags)
- SSO authentication (1Password, Google, Microsoft, Okta, Auth0)
- LDAP integration (Active Directory, OpenLDAP)
- Groups and distribution lists
- AI-powered spam detection (Bayesian classifier)
- ClamAV antivirus integration
- Comprehensive deployment options:
  - Docker and Docker Compose
  - Kubernetes manifests
  - Helm chart
  - AWS Terraform
  - Digital Ocean Terraform
  - One-click install script

### Changed
- Improved startup banner with security status

### Security
- Added automatic email encryption at rest
- Per-user encryption key pairs
- Secure key derivation with Argon2id

## [0.1.0] - 2025-01-03

### Added
- Initial release
- SMTP server (RFC 5321)
- IMAP server (RFC 3501)
- POP3 server (RFC 1939)
- Simple user management
- In-memory storage with JSON persistence
- Anti-spam filtering with rule-based scoring
- Basic anti-virus scanning
- CLI for administration
- Zero-configuration deployment
- Single binary distribution

[Unreleased]: https://github.com/pegasusheavy/kiss-mail/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pegasusheavy/kiss-mail/releases/tag/v0.1.0
