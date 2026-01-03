//! Shared mailbox storage for the KISS mail server.
//!
//! Provides a simple in-memory mail storage with file persistence.
//! Supports zero-knowledge encryption for emails at rest.

use crate::crypto::{CryptoManager, EncryptionMetadata};
use crate::ldap::{LdapAuthResult, LdapClient};
use crate::sso::SsoManager;
use crate::users::{UserAccount, UserManager};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// A single email message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email {
    pub id: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub raw: String,
    pub received_at: DateTime<Utc>,
    pub size: usize,
    pub seen: bool,
    pub deleted: bool,
    /// Encryption metadata (if encrypted at rest)
    #[serde(default)]
    pub encryption: EncryptionMetadata,
    /// Encrypted body (if encrypted)
    #[serde(default)]
    pub encrypted_body: Option<Vec<u8>>,
}

impl Email {
    pub fn new(from: String, to: Vec<String>, raw: String) -> Self {
        let (subject, headers, body) = Self::parse_raw(&raw);
        let size = raw.len();

        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to,
            subject,
            headers,
            body,
            raw,
            received_at: Utc::now(),
            size,
            seen: false,
            deleted: false,
            encryption: EncryptionMetadata::default(),
            encrypted_body: None,
        }
    }

    /// Create an encrypted email
    pub fn new_encrypted(
        from: String,
        to: Vec<String>,
        raw: String,
        encrypted_body: Vec<u8>,
        metadata: EncryptionMetadata,
    ) -> Self {
        let (subject, headers, _body) = Self::parse_raw(&raw);
        let size = raw.len();

        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to,
            subject,
            headers,
            body: "[Encrypted]".to_string(), // Placeholder for encrypted content
            raw: String::new(),              // Don't store unencrypted raw
            received_at: Utc::now(),
            size,
            seen: false,
            deleted: false,
            encryption: metadata,
            encrypted_body: Some(encrypted_body),
        }
    }

    /// Check if email is encrypted
    pub fn is_encrypted(&self) -> bool {
        self.encryption.encrypted
    }

    fn parse_raw(raw: &str) -> (String, Vec<(String, String)>, String) {
        let mut headers = Vec::new();
        let mut subject = String::new();
        let mut in_headers = true;
        let mut body_lines = Vec::new();
        let mut current_header: Option<(String, String)> = None;

        for line in raw.lines() {
            if in_headers {
                if line.is_empty() {
                    if let Some(h) = current_header.take() {
                        if h.0.to_lowercase() == "subject" {
                            subject = h.1.clone();
                        }
                        headers.push(h);
                    }
                    in_headers = false;
                    continue;
                }

                if line.starts_with(' ') || line.starts_with('\t') {
                    // Continuation of previous header
                    if let Some((_, ref mut val)) = current_header {
                        val.push(' ');
                        val.push_str(line.trim());
                    }
                } else if let Some(colon_pos) = line.find(':') {
                    if let Some(h) = current_header.take() {
                        if h.0.to_lowercase() == "subject" {
                            subject = h.1.clone();
                        }
                        headers.push(h);
                    }
                    let name = line[..colon_pos].to_string();
                    let value = line[colon_pos + 1..].trim().to_string();
                    current_header = Some((name, value));
                }
            } else {
                body_lines.push(line);
            }
        }

        if let Some(h) = current_header {
            if h.0.to_lowercase() == "subject" {
                subject = h.1.clone();
            }
            headers.push(h);
        }

        (subject, headers, body_lines.join("\r\n"))
    }

    pub fn get_header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| n.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

/// A user's mailbox containing their emails.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Mailbox {
    pub emails: Vec<Email>,
    pub uidvalidity: u32,
    pub uidnext: u32,
}

impl Mailbox {
    pub fn new() -> Self {
        Self {
            emails: Vec::new(),
            uidvalidity: 1,
            uidnext: 1,
        }
    }

    pub fn add_email(&mut self, email: Email) -> u32 {
        let uid = self.uidnext;
        self.uidnext += 1;
        self.emails.push(email);
        uid
    }

    pub fn get_active_emails(&self) -> Vec<&Email> {
        self.emails.iter().filter(|e| !e.deleted).collect()
    }

    pub fn expunge(&mut self) -> Vec<usize> {
        let mut removed = Vec::new();
        let mut i = 0;
        self.emails.retain(|e| {
            i += 1;
            if e.deleted {
                removed.push(i);
                false
            } else {
                true
            }
        });
        removed
    }
}

/// A user's mail data (mailbox only, credentials managed by UserManager).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMailbox {
    pub username: String,
    pub mailbox: Mailbox,
}

impl UserMailbox {
    pub fn new(username: String) -> Self {
        Self {
            username,
            mailbox: Mailbox::new(),
        }
    }
}

/// Legacy User struct for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
    pub mailbox: Mailbox,
}

impl User {
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            mailbox: Mailbox::new(),
        }
    }
}

/// The main storage backend.
#[derive(Clone)]
pub struct Storage {
    mailboxes: Arc<RwLock<HashMap<String, UserMailbox>>>,
    user_manager: Arc<UserManager>,
    ldap_client: Option<Arc<LdapClient>>,
    sso_manager: Option<Arc<SsoManager>>,
    crypto_manager: Option<Arc<CryptoManager>>,
    data_dir: PathBuf,
}

impl Storage {
    pub fn new(data_dir: PathBuf, user_manager: Arc<UserManager>) -> Self {
        Self {
            mailboxes: Arc::new(RwLock::new(HashMap::new())),
            user_manager,
            ldap_client: None,
            sso_manager: None,
            crypto_manager: None,
            data_dir,
        }
    }

    /// Create storage with LDAP support
    pub fn with_ldap(
        data_dir: PathBuf,
        user_manager: Arc<UserManager>,
        ldap_client: Arc<LdapClient>,
    ) -> Self {
        Self {
            mailboxes: Arc::new(RwLock::new(HashMap::new())),
            user_manager,
            ldap_client: Some(ldap_client),
            sso_manager: None,
            crypto_manager: None,
            data_dir,
        }
    }

    /// Create storage with LDAP and SSO support
    pub fn with_ldap_and_sso(
        data_dir: PathBuf,
        user_manager: Arc<UserManager>,
        ldap_client: Arc<LdapClient>,
        sso_manager: Arc<SsoManager>,
    ) -> Self {
        Self {
            mailboxes: Arc::new(RwLock::new(HashMap::new())),
            user_manager,
            ldap_client: Some(ldap_client),
            sso_manager: Some(sso_manager),
            crypto_manager: None,
            data_dir,
        }
    }

    /// Create storage with full encryption support
    pub fn with_encryption(
        data_dir: PathBuf,
        user_manager: Arc<UserManager>,
        ldap_client: Arc<LdapClient>,
        sso_manager: Arc<SsoManager>,
        crypto_manager: Arc<CryptoManager>,
    ) -> Self {
        Self {
            mailboxes: Arc::new(RwLock::new(HashMap::new())),
            user_manager,
            ldap_client: Some(ldap_client),
            sso_manager: Some(sso_manager),
            crypto_manager: Some(crypto_manager),
            data_dir,
        }
    }

    /// Set SSO manager
    pub fn set_sso_manager(&mut self, sso_manager: Arc<SsoManager>) {
        self.sso_manager = Some(sso_manager);
    }

    /// Set crypto manager
    pub fn set_crypto_manager(&mut self, crypto_manager: Arc<CryptoManager>) {
        self.crypto_manager = Some(crypto_manager);
    }

    /// Get encryption status
    pub fn encryption_enabled(&self) -> bool {
        self.crypto_manager
            .as_ref()
            .map(|c| c.is_enabled())
            .unwrap_or(false)
    }

    pub async fn load(&self) -> Result<(), std::io::Error> {
        // Load mailboxes
        let path = self.data_dir.join("mailboxes.json");
        if path.exists() {
            let data = tokio::fs::read_to_string(&path).await?;
            let mailboxes: HashMap<String, UserMailbox> = serde_json::from_str(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            *self.mailboxes.write().await = mailboxes;
            tracing::info!(
                "Loaded {} mailboxes from storage",
                self.mailboxes.read().await.len()
            );
        }

        // Migrate legacy users.json if it exists and mailboxes.json doesn't
        let legacy_path = self.data_dir.join("users.json");
        if legacy_path.exists() && !path.exists() {
            tracing::info!("Migrating legacy user data...");
            if let Ok(data) = tokio::fs::read_to_string(&legacy_path).await {
                if let Ok(legacy_users) = serde_json::from_str::<HashMap<String, User>>(&data) {
                    let mut mailboxes = self.mailboxes.write().await;
                    for (username, user) in legacy_users {
                        // Create user in UserManager if not exists
                        if !self.user_manager.user_exists(&username).await {
                            let _ = self
                                .user_manager
                                .create_user(&username, &user.password, None)
                                .await;
                        }
                        // Create mailbox entry
                        let mut user_mailbox = UserMailbox::new(username.clone());
                        user_mailbox.mailbox = user.mailbox;
                        mailboxes.insert(username, user_mailbox);
                    }
                    drop(mailboxes);
                    let _ = self.save().await;
                    tracing::info!("Migration complete");
                }
            }
        }

        Ok(())
    }

    pub async fn save(&self) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("mailboxes.json");
        let mailboxes = self.mailboxes.read().await;
        let data = serde_json::to_string_pretty(&*mailboxes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    /// Get the user manager
    pub fn user_manager(&self) -> &Arc<UserManager> {
        &self.user_manager
    }

    pub async fn create_user(&self, username: String, password: String) {
        // Create in user manager
        let _ = self
            .user_manager
            .create_user(&username, &password, None)
            .await;
        // Create mailbox
        let mut mailboxes = self.mailboxes.write().await;
        mailboxes.insert(username.clone(), UserMailbox::new(username));
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> bool {
        self.authenticate_with_ldap(username, password, "127.0.0.1", "internal")
            .await
            .is_ok()
    }

    /// Authenticate with full details (tries LDAP first, then local)
    pub async fn authenticate_full(
        &self,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
    ) -> Result<UserAccount, String> {
        self.authenticate_with_ldap(username, password, ip, protocol)
            .await
    }

    /// Internal authentication with LDAP and SSO support
    async fn authenticate_with_ldap(
        &self,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
    ) -> Result<UserAccount, String> {
        // Try SSO app password first if configured
        if let Some(ref sso) = self.sso_manager {
            if sso.verify_app_password(username, password, protocol).await {
                tracing::info!(
                    "SSO app password authentication successful for {}",
                    username
                );
                // Get or create local user
                if let Some(user) = self.user_manager.get_user(username).await {
                    return Ok(user);
                }
                // User exists in SSO but not locally - this shouldn't happen normally
                // but we can handle it by creating a minimal account
                let now = chrono::Utc::now();
                return Ok(UserAccount {
                    username: username.to_string(),
                    password_hash: String::new(),
                    domain: "sso".to_string(),
                    role: crate::users::UserRole::User,
                    status: crate::users::AccountStatus::Active,
                    quota: crate::users::UserQuota::default(),
                    settings: crate::users::UserSettings::default(),
                    created_at: now,
                    updated_at: now,
                    last_login: Some(now),
                    failed_login_attempts: 0,
                    last_failed_login: None,
                    login_history: vec![],
                    password_change_required: false,
                    password_changed_at: now,
                    allowed_ips: vec![],
                    admin_notes: None,
                });
            }
        }

        // Try LDAP if configured
        if let Some(ref ldap) = self.ldap_client {
            if ldap.is_enabled() {
                match ldap.authenticate(username, password).await {
                    LdapAuthResult::Success(ldap_user) => {
                        tracing::info!("LDAP authentication successful for {}", username);

                        // Ensure user exists locally (create if needed)
                        if !self.user_manager.user_exists(username).await {
                            // Auto-create local user from LDAP
                            let email = ldap_user.email.clone();
                            match self
                                .user_manager
                                .create_user(username, password, None)
                                .await
                            {
                                Ok(mut user) => {
                                    // Update with LDAP info
                                    if let Some(email) = email {
                                        user.settings.display_name = ldap_user.display_name.clone();
                                        // Store email for later use
                                        tracing::info!(
                                            "Created local user {} from LDAP ({})",
                                            username,
                                            email
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to create local user from LDAP: {}", e);
                                }
                            }
                        }

                        // Return the local user account (or create minimal one)
                        if let Some(user) = self.user_manager.get_user(username).await {
                            return Ok(user);
                        }

                        // Create a minimal account for LDAP-only users
                        let now = chrono::Utc::now();
                        return Ok(UserAccount {
                            username: username.to_string(),
                            password_hash: String::new(),
                            domain: "ldap".to_string(),
                            role: crate::users::UserRole::User,
                            status: crate::users::AccountStatus::Active,
                            quota: crate::users::UserQuota::default(),
                            settings: crate::users::UserSettings {
                                display_name: ldap_user.display_name,
                                ..Default::default()
                            },
                            created_at: now,
                            updated_at: now,
                            last_login: Some(now),
                            failed_login_attempts: 0,
                            last_failed_login: None,
                            login_history: vec![],
                            password_change_required: false,
                            password_changed_at: now,
                            allowed_ips: vec![],
                            admin_notes: None,
                        });
                    }
                    LdapAuthResult::InvalidCredentials => {
                        tracing::debug!(
                            "LDAP authentication failed for {}: invalid credentials",
                            username
                        );
                        if !ldap.fallback_enabled() {
                            return Err("Invalid credentials".to_string());
                        }
                        // Fall through to local auth
                    }
                    LdapAuthResult::UserNotFound => {
                        tracing::debug!("User {} not found in LDAP", username);
                        if !ldap.fallback_enabled() {
                            return Err("User not found".to_string());
                        }
                        // Fall through to local auth
                    }
                    LdapAuthResult::Error(e) => {
                        tracing::warn!("LDAP error for {}: {}", username, e);
                        if !ldap.fallback_enabled() {
                            return Err(format!("LDAP error: {}", e));
                        }
                        // Fall through to local auth
                    }
                    LdapAuthResult::NotEnabled => {
                        // Fall through to local auth
                    }
                }
            }
        }

        // Local authentication
        self.user_manager
            .authenticate(username, password, ip, protocol)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn user_exists(&self, username: &str) -> bool {
        self.user_manager.user_exists(username).await
    }

    pub async fn deliver_email(&self, recipient: &str, email: Email) -> Result<(), String> {
        // Extract local part from email address
        let local_part = recipient
            .split('@')
            .next()
            .unwrap_or(recipient)
            .to_lowercase();

        // Check if user exists
        if !self.user_manager.user_exists(&local_part).await {
            // Auto-create user for local delivery (KISS approach)
            let password = generate_random_password();
            if let Err(e) = self
                .user_manager
                .create_user(&local_part, &password, None)
                .await
            {
                tracing::warn!("Could not auto-create user {}: {}", local_part, e);
            } else {
                tracing::info!("Auto-created user {} for email delivery", local_part);
            }
        }

        // Check user quota
        if let Some(user) = self.user_manager.get_user(&local_part).await {
            if let Err(e) = user.quota.can_receive(email.size as u64) {
                return Err(format!("Quota exceeded: {}", e));
            }
        }

        // Encrypt email if crypto is enabled
        let email_to_store = if let Some(crypto) = &self.crypto_manager {
            if crypto.is_enabled() && crypto.has_keys(&local_part).await {
                // Encrypt the email body for storage
                match crypto
                    .encrypt_for_storage(&local_part, email.raw.as_bytes())
                    .await
                {
                    Ok((encrypted_body, metadata)) => {
                        tracing::debug!("Encrypted email for {}", local_part);
                        Email::new_encrypted(
                            email.from,
                            email.to,
                            email.raw.clone(), // Keep for metadata parsing only
                            encrypted_body,
                            metadata,
                        )
                    }
                    Err(e) => {
                        tracing::warn!("Failed to encrypt email for {}: {}", local_part, e);
                        email
                    }
                }
            } else {
                email
            }
        } else {
            email
        };

        // Deliver to mailbox
        let mut mailboxes = self.mailboxes.write().await;

        let user_mailbox = mailboxes
            .entry(local_part.clone())
            .or_insert_with(|| UserMailbox::new(local_part.clone()));

        let email_size = email_to_store.size;
        user_mailbox.mailbox.add_email(email_to_store);

        // Update user quota
        drop(mailboxes);
        let _ = self
            .user_manager
            .update_user(&local_part, |u| {
                u.quota.record_received(email_size as u64);
            })
            .await;

        tracing::info!(
            "Delivered email to {} (encrypted: {})",
            local_part,
            self.encryption_enabled()
        );
        Ok(())
    }

    /// Decrypt an email for a user (requires active session)
    pub async fn decrypt_email(&self, username: &str, email: &Email) -> Result<String, String> {
        if !email.is_encrypted() {
            return Ok(email.raw.clone());
        }

        let crypto = self
            .crypto_manager
            .as_ref()
            .ok_or_else(|| "Encryption not configured".to_string())?;

        let encrypted_body = email
            .encrypted_body
            .as_ref()
            .ok_or_else(|| "Email marked as encrypted but no encrypted body".to_string())?;

        let decrypted = crypto
            .decrypt_from_storage(username, encrypted_body, &email.encryption)
            .await
            .map_err(|e| e.to_string())?;

        String::from_utf8(decrypted).map_err(|e| format!("Invalid UTF-8 in decrypted email: {}", e))
    }

    pub async fn get_mailbox(&self, username: &str) -> Option<Mailbox> {
        let mailboxes = self.mailboxes.read().await;
        mailboxes.get(username).map(|u| u.mailbox.clone())
    }

    pub async fn update_mailbox<F>(&self, username: &str, f: F)
    where
        F: FnOnce(&mut Mailbox),
    {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(user_mailbox) = mailboxes.get_mut(username) {
            f(&mut user_mailbox.mailbox);
        }
    }

    pub async fn mark_seen(&self, username: &str, email_idx: usize) {
        self.update_mailbox(username, |mb| {
            if let Some(email) = mb.emails.get_mut(email_idx) {
                email.seen = true;
            }
        })
        .await;
    }

    pub async fn mark_deleted(&self, username: &str, email_idx: usize, deleted: bool) {
        self.update_mailbox(username, |mb| {
            if let Some(email) = mb.emails.get_mut(email_idx) {
                email.deleted = deleted;
            }
        })
        .await;
    }

    pub async fn expunge(&self, username: &str) -> Vec<usize> {
        let mut mailboxes = self.mailboxes.write().await;
        if let Some(user_mailbox) = mailboxes.get_mut(username) {
            let mut removed = Vec::new();
            let mut deleted_size: u64 = 0;
            let mut i = 0;

            user_mailbox.mailbox.emails.retain(|e| {
                i += 1;
                if e.deleted {
                    removed.push(i);
                    deleted_size += e.size as u64;
                    false
                } else {
                    true
                }
            });

            // Update quota
            drop(mailboxes);
            if deleted_size > 0 {
                let _ = self
                    .user_manager
                    .update_user(username, |u| {
                        u.quota.current_usage = u.quota.current_usage.saturating_sub(deleted_size);
                        u.quota.current_messages = u
                            .quota
                            .current_messages
                            .saturating_sub(removed.len() as u32);
                    })
                    .await;
            }

            removed
        } else {
            Vec::new()
        }
    }

    /// Get storage statistics
    pub async fn get_stats(&self) -> StorageStats {
        let mailboxes = self.mailboxes.read().await;
        let user_stats = self.user_manager.get_stats().await;

        let mut total_emails = 0u64;
        let mut total_size = 0u64;

        for mb in mailboxes.values() {
            total_emails += mb.mailbox.emails.len() as u64;
            total_size += mb.mailbox.emails.iter().map(|e| e.size as u64).sum::<u64>();
        }

        StorageStats {
            total_mailboxes: mailboxes.len() as u32,
            total_emails,
            total_size,
            user_stats,
        }
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_mailboxes: u32,
    pub total_emails: u64,
    pub total_size: u64,
    pub user_stats: crate::users::UserStats,
}

/// Generate a random password for auto-created users
fn generate_random_password() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        .chars()
        .collect();
    (0..16)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect()
}
