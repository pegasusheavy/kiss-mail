//! Comprehensive user management module.
//!
//! Provides user CRUD operations, authentication, roles, quotas, and admin functions.

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// User role for access control
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    /// Regular user - can send/receive emails
    #[default]
    User,
    /// Administrator - can manage users and server settings
    Admin,
    /// Super administrator - full access including other admins
    SuperAdmin,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::User => write!(f, "user"),
            UserRole::Admin => write!(f, "admin"),
            UserRole::SuperAdmin => write!(f, "superadmin"),
        }
    }
}

/// Account status
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountStatus {
    /// Account is active and can be used
    #[default]
    Active,
    /// Account is suspended (can't login)
    Suspended,
    /// Account is locked due to failed login attempts
    Locked,
    /// Account is pending email verification
    PendingVerification,
    /// Account is disabled permanently
    Disabled,
}

impl std::fmt::Display for AccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccountStatus::Active => write!(f, "active"),
            AccountStatus::Suspended => write!(f, "suspended"),
            AccountStatus::Locked => write!(f, "locked"),
            AccountStatus::PendingVerification => write!(f, "pending"),
            AccountStatus::Disabled => write!(f, "disabled"),
        }
    }
}

/// User quota settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserQuota {
    /// Maximum mailbox size in bytes (0 = unlimited)
    pub max_mailbox_size: u64,
    /// Maximum single message size in bytes
    pub max_message_size: u64,
    /// Maximum number of messages (0 = unlimited)
    pub max_messages: u32,
    /// Maximum outgoing emails per day (0 = unlimited)
    pub max_outgoing_per_day: u32,
    /// Current mailbox usage in bytes
    pub current_usage: u64,
    /// Current message count
    pub current_messages: u32,
    /// Outgoing emails sent today
    pub outgoing_today: u32,
    /// Date of last outgoing count reset
    pub outgoing_reset_date: DateTime<Utc>,
}

impl Default for UserQuota {
    fn default() -> Self {
        Self {
            max_mailbox_size: 100 * 1024 * 1024, // 100MB
            max_message_size: 25 * 1024 * 1024,  // 25MB
            max_messages: 10000,
            max_outgoing_per_day: 500,
            current_usage: 0,
            current_messages: 0,
            outgoing_today: 0,
            outgoing_reset_date: Utc::now(),
        }
    }
}

impl UserQuota {
    /// Check if user can receive a message of given size
    pub fn can_receive(&self, message_size: u64) -> Result<(), QuotaError> {
        if self.max_message_size > 0 && message_size > self.max_message_size {
            return Err(QuotaError::MessageTooLarge {
                size: message_size,
                max: self.max_message_size,
            });
        }

        if self.max_mailbox_size > 0 && self.current_usage + message_size > self.max_mailbox_size {
            return Err(QuotaError::MailboxFull {
                current: self.current_usage,
                max: self.max_mailbox_size,
            });
        }

        if self.max_messages > 0 && self.current_messages >= self.max_messages {
            return Err(QuotaError::TooManyMessages {
                current: self.current_messages,
                max: self.max_messages,
            });
        }

        Ok(())
    }

    /// Check if user can send an outgoing email
    pub fn can_send(&mut self) -> Result<(), QuotaError> {
        // Reset counter if it's a new day
        let today = Utc::now().date_naive();
        if self.outgoing_reset_date.date_naive() != today {
            self.outgoing_today = 0;
            self.outgoing_reset_date = Utc::now();
        }

        if self.max_outgoing_per_day > 0 && self.outgoing_today >= self.max_outgoing_per_day {
            return Err(QuotaError::DailyLimitReached {
                current: self.outgoing_today,
                max: self.max_outgoing_per_day,
            });
        }

        Ok(())
    }

    /// Record a sent message
    pub fn record_sent(&mut self) {
        self.outgoing_today += 1;
    }

    /// Record a received message
    pub fn record_received(&mut self, size: u64) {
        self.current_usage += size;
        self.current_messages += 1;
    }

    /// Record a deleted message
    pub fn record_deleted(&mut self, size: u64) {
        self.current_usage = self.current_usage.saturating_sub(size);
        self.current_messages = self.current_messages.saturating_sub(1);
    }

    /// Get usage percentage
    pub fn usage_percent(&self) -> f32 {
        if self.max_mailbox_size == 0 {
            return 0.0;
        }
        (self.current_usage as f32 / self.max_mailbox_size as f32) * 100.0
    }
}

/// Quota error types
#[derive(Debug, Clone)]
pub enum QuotaError {
    MessageTooLarge { size: u64, max: u64 },
    MailboxFull { current: u64, max: u64 },
    TooManyMessages { current: u32, max: u32 },
    DailyLimitReached { current: u32, max: u32 },
}

impl std::fmt::Display for QuotaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuotaError::MessageTooLarge { size, max } => {
                write!(f, "Message too large: {} bytes (max: {} bytes)", size, max)
            }
            QuotaError::MailboxFull { current, max } => {
                write!(f, "Mailbox full: {} / {} bytes", current, max)
            }
            QuotaError::TooManyMessages { current, max } => {
                write!(f, "Too many messages: {} / {}", current, max)
            }
            QuotaError::DailyLimitReached { current, max } => {
                write!(f, "Daily sending limit reached: {} / {}", current, max)
            }
        }
    }
}

/// User settings and preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    /// Display name
    pub display_name: Option<String>,
    /// Auto-reply message (vacation responder)
    pub auto_reply: Option<String>,
    /// Auto-reply enabled
    pub auto_reply_enabled: bool,
    /// Forward emails to another address
    pub forward_to: Option<String>,
    /// Keep copy when forwarding
    pub forward_keep_copy: bool,
    /// Signature for outgoing emails
    pub signature: Option<String>,
    /// Preferred language
    pub language: String,
    /// Timezone
    pub timezone: String,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            display_name: None,
            auto_reply: None,
            auto_reply_enabled: false,
            forward_to: None,
            forward_keep_copy: true,
            signature: None,
            language: "en".to_string(),
            timezone: "UTC".to_string(),
        }
    }
}

/// Login history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRecord {
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub protocol: String, // SMTP, IMAP, POP3
    pub success: bool,
    pub failure_reason: Option<String>,
}

/// Complete user account
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    /// Unique username (email local part)
    pub username: String,
    /// Hashed password (Argon2)
    pub password_hash: String,
    /// User's email domain
    pub domain: String,
    /// User role
    pub role: UserRole,
    /// Account status
    pub status: AccountStatus,
    /// Quota settings
    pub quota: UserQuota,
    /// User settings
    pub settings: UserSettings,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
    /// Last successful login
    pub last_login: Option<DateTime<Utc>>,
    /// Failed login attempts (reset on successful login)
    pub failed_login_attempts: u32,
    /// Last failed login attempt
    pub last_failed_login: Option<DateTime<Utc>>,
    /// Login history (last N entries)
    pub login_history: Vec<LoginRecord>,
    /// Password change required on next login
    pub password_change_required: bool,
    /// Password last changed
    pub password_changed_at: DateTime<Utc>,
    /// Allowed IP addresses (empty = all allowed)
    pub allowed_ips: Vec<String>,
    /// Account notes (admin only)
    pub admin_notes: Option<String>,
}

impl UserAccount {
    /// Create a new user account
    pub fn new(username: String, password: &str, domain: String) -> Result<Self, String> {
        let password_hash = hash_password(password)?;
        let now = Utc::now();

        Ok(Self {
            username,
            password_hash,
            domain,
            role: UserRole::User,
            status: AccountStatus::Active,
            quota: UserQuota::default(),
            settings: UserSettings::default(),
            created_at: now,
            updated_at: now,
            last_login: None,
            failed_login_attempts: 0,
            last_failed_login: None,
            login_history: Vec::new(),
            password_change_required: false,
            password_changed_at: now,
            allowed_ips: Vec::new(),
            admin_notes: None,
        })
    }

    /// Get the full email address
    pub fn email(&self) -> String {
        format!("{}@{}", self.username, self.domain)
    }

    /// Verify password
    pub fn verify_password(&self, password: &str) -> bool {
        verify_password(password, &self.password_hash)
    }

    /// Change password
    pub fn change_password(&mut self, new_password: &str) -> Result<(), String> {
        self.password_hash = hash_password(new_password)?;
        self.password_changed_at = Utc::now();
        self.password_change_required = false;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Record a login attempt
    pub fn record_login(
        &mut self,
        ip: &str,
        protocol: &str,
        success: bool,
        failure_reason: Option<&str>,
    ) {
        let record = LoginRecord {
            timestamp: Utc::now(),
            ip_address: ip.to_string(),
            protocol: protocol.to_string(),
            success,
            failure_reason: failure_reason.map(String::from),
        };

        self.login_history.push(record);

        // Keep only last 100 login records
        if self.login_history.len() > 100 {
            self.login_history.remove(0);
        }

        if success {
            self.last_login = Some(Utc::now());
            self.failed_login_attempts = 0;
        } else {
            self.failed_login_attempts += 1;
            self.last_failed_login = Some(Utc::now());

            // Auto-lock after 5 failed attempts
            if self.failed_login_attempts >= 5 {
                self.status = AccountStatus::Locked;
            }
        }
    }

    /// Check if account can login
    pub fn can_login(&self) -> Result<(), String> {
        match self.status {
            AccountStatus::Active => Ok(()),
            AccountStatus::Suspended => Err("Account is suspended".to_string()),
            AccountStatus::Locked => {
                Err("Account is locked due to too many failed login attempts".to_string())
            }
            AccountStatus::PendingVerification => {
                Err("Account is pending email verification".to_string())
            }
            AccountStatus::Disabled => Err("Account is disabled".to_string()),
        }
    }

    /// Check if IP is allowed
    pub fn is_ip_allowed(&self, ip: &str) -> bool {
        if self.allowed_ips.is_empty() {
            return true;
        }
        self.allowed_ips.iter().any(|allowed| {
            allowed == ip || allowed == "*" || ip.starts_with(allowed.trim_end_matches('*'))
        })
    }
}

/// Hash a password using Argon2
fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

/// Verify a password against a hash
fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// User management errors
#[derive(Debug, Clone)]
pub enum UserError {
    NotFound(String),
    AlreadyExists(String),
    InvalidPassword(String),
    PermissionDenied(String),
    AccountLocked(String),
    QuotaExceeded(QuotaError),
    InvalidInput(String),
    StorageError(String),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserError::NotFound(msg) => write!(f, "User not found: {}", msg),
            UserError::AlreadyExists(msg) => write!(f, "User already exists: {}", msg),
            UserError::InvalidPassword(msg) => write!(f, "Invalid password: {}", msg),
            UserError::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            UserError::AccountLocked(msg) => write!(f, "Account locked: {}", msg),
            UserError::QuotaExceeded(err) => write!(f, "Quota exceeded: {}", err),
            UserError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            UserError::StorageError(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

/// User manager for CRUD operations
#[derive(Debug)]
pub struct UserManager {
    users: Arc<RwLock<HashMap<String, UserAccount>>>,
    default_domain: String,
    data_dir: PathBuf,
}

impl UserManager {
    pub fn new(default_domain: String, data_dir: PathBuf) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            default_domain,
            data_dir,
        }
    }

    /// Load users from storage
    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("users.json");
        if path.exists() {
            let data = tokio::fs::read_to_string(&path).await?;
            let users: HashMap<String, UserAccount> = serde_json::from_str(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            *self.users.write().await = users;
            tracing::info!("Loaded {} user accounts", self.users.read().await.len());
        }
        Ok(())
    }

    /// Save users to storage
    pub async fn save(&self) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("users.json");
        let users = self.users.read().await;
        let data = serde_json::to_string_pretty(&*users)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    /// Create a new user
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: Option<UserRole>,
    ) -> Result<UserAccount, UserError> {
        // Validate username
        let username = username.to_lowercase().trim().to_string();
        if username.is_empty() {
            return Err(UserError::InvalidInput(
                "Username cannot be empty".to_string(),
            ));
        }
        if username.len() > 64 {
            return Err(UserError::InvalidInput("Username too long".to_string()));
        }
        if !username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '_' || c == '-')
        {
            return Err(UserError::InvalidInput(
                "Username can only contain letters, numbers, dots, underscores, and hyphens"
                    .to_string(),
            ));
        }

        // Validate password
        if password.len() < 8 {
            return Err(UserError::InvalidPassword(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        let mut users = self.users.write().await;

        if users.contains_key(&username) {
            return Err(UserError::AlreadyExists(username));
        }

        let mut account = UserAccount::new(username.clone(), password, self.default_domain.clone())
            .map_err(UserError::StorageError)?;

        if let Some(r) = role {
            account.role = r;
        }

        users.insert(username.clone(), account.clone());
        drop(users);

        let _ = self.save().await;

        tracing::info!("Created user account: {}", username);
        Ok(account)
    }

    /// Get a user by username
    pub async fn get_user(&self, username: &str) -> Option<UserAccount> {
        let username = username.to_lowercase();
        self.users.read().await.get(&username).cloned()
    }

    /// Check if a user exists
    pub async fn user_exists(&self, username: &str) -> bool {
        let username = username.to_lowercase();
        self.users.read().await.contains_key(&username)
    }

    /// Update a user
    pub async fn update_user<F>(
        &self,
        username: &str,
        update_fn: F,
    ) -> Result<UserAccount, UserError>
    where
        F: FnOnce(&mut UserAccount),
    {
        let username = username.to_lowercase();
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        update_fn(user);
        user.updated_at = Utc::now();

        let updated = user.clone();
        drop(users);

        let _ = self.save().await;

        Ok(updated)
    }

    /// Delete a user
    pub async fn delete_user(&self, username: &str, actor: &UserAccount) -> Result<(), UserError> {
        let username = username.to_lowercase();

        // Check permissions
        if actor.role == UserRole::User {
            return Err(UserError::PermissionDenied(
                "Only administrators can delete users".to_string(),
            ));
        }

        let mut users = self.users.write().await;

        let target = users
            .get(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // SuperAdmins can only be deleted by other SuperAdmins
        if target.role == UserRole::SuperAdmin && actor.role != UserRole::SuperAdmin {
            return Err(UserError::PermissionDenied(
                "Only super administrators can delete super administrators".to_string(),
            ));
        }

        // Can't delete yourself
        if target.username == actor.username {
            return Err(UserError::PermissionDenied(
                "Cannot delete your own account".to_string(),
            ));
        }

        users.remove(&username);
        drop(users);

        let _ = self.save().await;

        tracing::info!("Deleted user account: {} (by {})", username, actor.username);
        Ok(())
    }

    /// Authenticate a user
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
        ip: &str,
        protocol: &str,
    ) -> Result<UserAccount, UserError> {
        let username = username.to_lowercase();
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // Check if account can login
        user.can_login().map_err(UserError::AccountLocked)?;

        // Check IP restrictions
        if !user.is_ip_allowed(ip) {
            user.record_login(ip, protocol, false, Some("IP not allowed"));
            return Err(UserError::PermissionDenied(format!(
                "Login from IP {} is not allowed",
                ip
            )));
        }

        // Verify password
        if !user.verify_password(password) {
            user.record_login(ip, protocol, false, Some("Invalid password"));
            let attempts = user.failed_login_attempts;
            drop(users);
            let _ = self.save().await;

            return Err(UserError::InvalidPassword(format!(
                "Invalid password ({} failed attempts)",
                attempts
            )));
        }

        // Success
        user.record_login(ip, protocol, true, None);
        let authenticated = user.clone();
        drop(users);

        let _ = self.save().await;

        tracing::info!(
            "User {} authenticated via {} from {}",
            username,
            protocol,
            ip
        );
        Ok(authenticated)
    }

    /// Change user password
    pub async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), UserError> {
        let username = username.to_lowercase();

        // Validate new password
        if new_password.len() < 8 {
            return Err(UserError::InvalidPassword(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // Verify old password
        if !user.verify_password(old_password) {
            return Err(UserError::InvalidPassword(
                "Current password is incorrect".to_string(),
            ));
        }

        user.change_password(new_password)
            .map_err(UserError::StorageError)?;

        drop(users);
        let _ = self.save().await;

        tracing::info!("Password changed for user: {}", username);
        Ok(())
    }

    /// Admin reset password (no old password needed)
    pub async fn admin_reset_password(
        &self,
        username: &str,
        new_password: &str,
        actor: &UserAccount,
        require_change: bool,
    ) -> Result<(), UserError> {
        // Check permissions
        if actor.role == UserRole::User {
            return Err(UserError::PermissionDenied(
                "Only administrators can reset passwords".to_string(),
            ));
        }

        let username = username.to_lowercase();

        // Validate new password
        if new_password.len() < 8 {
            return Err(UserError::InvalidPassword(
                "Password must be at least 8 characters".to_string(),
            ));
        }

        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // SuperAdmins can only have password reset by other SuperAdmins
        if user.role == UserRole::SuperAdmin && actor.role != UserRole::SuperAdmin {
            return Err(UserError::PermissionDenied(
                "Only super administrators can reset super administrator passwords".to_string(),
            ));
        }

        user.change_password(new_password)
            .map_err(UserError::StorageError)?;
        user.password_change_required = require_change;

        // Unlock if locked
        if user.status == AccountStatus::Locked {
            user.status = AccountStatus::Active;
            user.failed_login_attempts = 0;
        }

        drop(users);
        let _ = self.save().await;

        tracing::info!(
            "Password reset for user: {} (by {})",
            username,
            actor.username
        );
        Ok(())
    }

    /// Set user status
    pub async fn set_status(
        &self,
        username: &str,
        status: AccountStatus,
        actor: &UserAccount,
    ) -> Result<(), UserError> {
        // Check permissions
        if actor.role == UserRole::User {
            return Err(UserError::PermissionDenied(
                "Only administrators can change user status".to_string(),
            ));
        }

        let username = username.to_lowercase();
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // SuperAdmins can only be modified by other SuperAdmins
        if user.role == UserRole::SuperAdmin && actor.role != UserRole::SuperAdmin {
            return Err(UserError::PermissionDenied(
                "Only super administrators can modify super administrators".to_string(),
            ));
        }

        let old_status = user.status;
        user.status = status;
        user.updated_at = Utc::now();

        // Reset failed attempts if unlocking
        if old_status == AccountStatus::Locked && status == AccountStatus::Active {
            user.failed_login_attempts = 0;
        }

        drop(users);
        let _ = self.save().await;

        tracing::info!(
            "Status changed for user {}: {:?} -> {:?} (by {})",
            username,
            old_status,
            status,
            actor.username
        );
        Ok(())
    }

    /// Set user role
    pub async fn set_role(
        &self,
        username: &str,
        role: UserRole,
        actor: &UserAccount,
    ) -> Result<(), UserError> {
        // Only SuperAdmins can change roles
        if actor.role != UserRole::SuperAdmin {
            return Err(UserError::PermissionDenied(
                "Only super administrators can change user roles".to_string(),
            ));
        }

        let username = username.to_lowercase();
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // Can't change your own role
        if user.username == actor.username {
            return Err(UserError::PermissionDenied(
                "Cannot change your own role".to_string(),
            ));
        }

        let old_role = user.role;
        user.role = role;
        user.updated_at = Utc::now();

        drop(users);
        let _ = self.save().await;

        tracing::info!(
            "Role changed for user {}: {:?} -> {:?} (by {})",
            username,
            old_role,
            role,
            actor.username
        );
        Ok(())
    }

    /// Set user quota
    pub async fn set_quota(
        &self,
        username: &str,
        quota: UserQuota,
        actor: &UserAccount,
    ) -> Result<(), UserError> {
        // Check permissions
        if actor.role == UserRole::User {
            return Err(UserError::PermissionDenied(
                "Only administrators can change user quotas".to_string(),
            ));
        }

        let username = username.to_lowercase();
        let mut users = self.users.write().await;

        let user = users
            .get_mut(&username)
            .ok_or_else(|| UserError::NotFound(username.clone()))?;

        // Preserve current usage stats
        let current_usage = user.quota.current_usage;
        let current_messages = user.quota.current_messages;
        let outgoing_today = user.quota.outgoing_today;
        let outgoing_reset_date = user.quota.outgoing_reset_date;

        user.quota = quota;
        user.quota.current_usage = current_usage;
        user.quota.current_messages = current_messages;
        user.quota.outgoing_today = outgoing_today;
        user.quota.outgoing_reset_date = outgoing_reset_date;
        user.updated_at = Utc::now();

        drop(users);
        let _ = self.save().await;

        tracing::info!(
            "Quota updated for user {} (by {})",
            username,
            actor.username
        );
        Ok(())
    }

    /// List all users
    pub async fn list_users(&self) -> Vec<UserAccount> {
        self.users.read().await.values().cloned().collect()
    }

    /// List users with filtering
    pub async fn list_users_filtered(
        &self,
        role: Option<UserRole>,
        status: Option<AccountStatus>,
        search: Option<&str>,
    ) -> Vec<UserAccount> {
        self.users
            .read()
            .await
            .values()
            .filter(|u| {
                if let Some(r) = role {
                    if u.role != r {
                        return false;
                    }
                }
                if let Some(s) = status {
                    if u.status != s {
                        return false;
                    }
                }
                if let Some(q) = search {
                    let q = q.to_lowercase();
                    if !u.username.contains(&q)
                        && !u.email().contains(&q)
                        && !u
                            .settings
                            .display_name
                            .as_ref()
                            .is_some_and(|n| n.to_lowercase().contains(&q))
                    {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect()
    }

    /// Get user statistics
    #[allow(clippy::field_reassign_with_default)]
    pub async fn get_stats(&self) -> UserStats {
        let users = self.users.read().await;

        let mut stats = UserStats::default();
        stats.total_users = users.len() as u32;

        for user in users.values() {
            match user.status {
                AccountStatus::Active => stats.active_users += 1,
                AccountStatus::Suspended => stats.suspended_users += 1,
                AccountStatus::Locked => stats.locked_users += 1,
                AccountStatus::PendingVerification => stats.pending_users += 1,
                AccountStatus::Disabled => stats.disabled_users += 1,
            }

            match user.role {
                UserRole::User => stats.regular_users += 1,
                UserRole::Admin => stats.admin_users += 1,
                UserRole::SuperAdmin => stats.superadmin_users += 1,
            }

            stats.total_storage_used += user.quota.current_usage;
            stats.total_messages += user.quota.current_messages as u64;
        }

        stats
    }

    /// Create initial admin user if no users exist
    pub async fn ensure_admin(&self, password: &str) -> Result<Option<UserAccount>, UserError> {
        let users = self.users.read().await;
        if !users.is_empty() {
            return Ok(None);
        }
        drop(users);

        let mut admin = self
            .create_user("admin", password, Some(UserRole::SuperAdmin))
            .await?;
        admin.settings.display_name = Some("System Administrator".to_string());

        self.update_user("admin", |u| {
            u.settings.display_name = Some("System Administrator".to_string());
        })
        .await?;

        tracing::info!("Created initial admin user");
        Ok(Some(admin))
    }
}

/// User statistics
#[derive(Debug, Default, Clone)]
pub struct UserStats {
    pub total_users: u32,
    pub active_users: u32,
    pub suspended_users: u32,
    pub locked_users: u32,
    pub pending_users: u32,
    pub disabled_users: u32,
    pub regular_users: u32,
    pub admin_users: u32,
    pub superadmin_users: u32,
    pub total_storage_used: u64,
    pub total_messages: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash));
        assert!(!verify_password("wrong_password", &hash));
    }

    #[test]
    fn test_user_account_creation() {
        let account = UserAccount::new(
            "testuser".to_string(),
            "password123",
            "example.com".to_string(),
        )
        .unwrap();

        assert_eq!(account.username, "testuser");
        assert_eq!(account.domain, "example.com");
        assert_eq!(account.email(), "testuser@example.com");
        assert!(account.verify_password("password123"));
        assert!(!account.verify_password("wrongpassword"));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_quota_checks() {
        let mut quota = UserQuota::default();
        quota.max_mailbox_size = 1000;
        quota.max_message_size = 500;
        quota.max_messages = 10;

        assert!(quota.can_receive(100).is_ok());
        assert!(quota.can_receive(600).is_err()); // Too large

        quota.current_usage = 900;
        assert!(quota.can_receive(200).is_err()); // Would exceed mailbox

        quota.current_messages = 10;
        assert!(quota.can_receive(50).is_err()); // Too many messages
    }

    #[test]
    fn test_account_locking() {
        let mut account = UserAccount::new(
            "testuser".to_string(),
            "password123",
            "example.com".to_string(),
        )
        .unwrap();

        // Simulate failed logins
        for _ in 0..5 {
            account.record_login("127.0.0.1", "IMAP", false, Some("bad password"));
        }

        assert_eq!(account.status, AccountStatus::Locked);
        assert!(account.can_login().is_err());
    }

    #[tokio::test]
    async fn test_user_manager() {
        let manager =
            UserManager::new("test.com".to_string(), PathBuf::from("/tmp/kiss-mail-test"));

        // Create user
        let user = manager
            .create_user("john", "password123", None)
            .await
            .unwrap();
        assert_eq!(user.username, "john");
        assert_eq!(user.role, UserRole::User);

        // Check exists
        assert!(manager.user_exists("john").await);
        assert!(!manager.user_exists("jane").await);

        // Get user
        let retrieved = manager.get_user("john").await.unwrap();
        assert_eq!(retrieved.username, "john");

        // Duplicate should fail
        assert!(
            manager
                .create_user("john", "password456", None)
                .await
                .is_err()
        );
    }
}
