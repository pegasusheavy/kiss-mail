//! SSO (Single Sign-On) integration module.
//!
//! Provides OIDC/OAuth2 authentication for SSO providers:
//! - 1Password
//! - Google Workspace
//! - Microsoft Entra ID (Azure AD)
//! - Okta
//! - Auth0
//! - Keycloak
//! - Any OIDC-compliant provider
//!
//! For email clients that don't support OAuth2, app passwords can be generated.

use chrono::{DateTime, Duration, Utc};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Well-known OIDC provider configurations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SsoProvider {
    /// 1Password Business/Enterprise
    OnePassword,
    /// Google Workspace
    Google,
    /// Microsoft Entra ID (Azure AD)
    Microsoft,
    /// Okta
    Okta,
    /// Auth0
    Auth0,
    /// Keycloak
    Keycloak,
    /// Generic OIDC provider
    Generic,
}

impl SsoProvider {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::OnePassword => "1Password",
            Self::Google => "Google",
            Self::Microsoft => "Microsoft",
            Self::Okta => "Okta",
            Self::Auth0 => "Auth0",
            Self::Keycloak => "Keycloak",
            Self::Generic => "OIDC",
        }
    }
}

/// SSO configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    /// SSO enabled
    pub enabled: bool,
    /// SSO provider type
    pub provider: SsoProvider,
    /// OAuth2 Client ID
    pub client_id: String,
    /// OAuth2 Client Secret
    pub client_secret: String,
    /// Authorization endpoint URL
    pub auth_url: String,
    /// Token endpoint URL
    pub token_url: String,
    /// UserInfo endpoint URL (optional)
    pub userinfo_url: Option<String>,
    /// OIDC issuer URL (for discovery)
    pub issuer_url: Option<String>,
    /// Redirect URI for OAuth2 callback
    pub redirect_uri: String,
    /// Required scopes
    pub scopes: Vec<String>,
    /// Map OIDC claims to username
    pub username_claim: String,
    /// Map OIDC claims to email
    pub email_claim: String,
    /// Map OIDC claims to display name
    pub name_claim: String,
    /// Allow app passwords for mail clients
    pub allow_app_passwords: bool,
    /// App password length
    pub app_password_length: usize,
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: SsoProvider::Generic,
            client_id: String::new(),
            client_secret: String::new(),
            auth_url: String::new(),
            token_url: String::new(),
            userinfo_url: None,
            issuer_url: None,
            redirect_uri: "http://localhost:8080/callback".to_string(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            username_claim: "preferred_username".to_string(),
            email_claim: "email".to_string(),
            name_claim: "name".to_string(),
            allow_app_passwords: true,
            app_password_length: 24,
        }
    }
}

impl SsoConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Check for provider-specific env vars first
        if let Ok(client_id) = std::env::var("ONEPASSWORD_CLIENT_ID") {
            config.provider = SsoProvider::OnePassword;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("ONEPASSWORD_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            // 1Password uses their own SSO endpoints
            config.auth_url = std::env::var("ONEPASSWORD_AUTH_URL")
                .unwrap_or_else(|_| "https://app.1password.com/oauth/authorize".to_string());
            config.token_url = std::env::var("ONEPASSWORD_TOKEN_URL")
                .unwrap_or_else(|_| "https://app.1password.com/oauth/token".to_string());
        } else if let Ok(client_id) = std::env::var("GOOGLE_CLIENT_ID") {
            config.provider = SsoProvider::Google;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("GOOGLE_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            config.auth_url = "https://accounts.google.com/o/oauth2/v2/auth".to_string();
            config.token_url = "https://oauth2.googleapis.com/token".to_string();
            config.userinfo_url =
                Some("https://openidconnect.googleapis.com/v1/userinfo".to_string());
        } else if let Ok(client_id) = std::env::var("MICROSOFT_CLIENT_ID") {
            config.provider = SsoProvider::Microsoft;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("MICROSOFT_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            let tenant =
                std::env::var("MICROSOFT_TENANT_ID").unwrap_or_else(|_| "common".to_string());
            config.auth_url = format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                tenant
            );
            config.token_url = format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                tenant
            );
            config.userinfo_url = Some("https://graph.microsoft.com/oidc/userinfo".to_string());
        } else if let Ok(client_id) = std::env::var("OKTA_CLIENT_ID") {
            config.provider = SsoProvider::Okta;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("OKTA_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            if let Ok(domain) = std::env::var("OKTA_DOMAIN") {
                config.auth_url = format!("https://{}/oauth2/default/v1/authorize", domain);
                config.token_url = format!("https://{}/oauth2/default/v1/token", domain);
                config.userinfo_url =
                    Some(format!("https://{}/oauth2/default/v1/userinfo", domain));
            }
        } else if let Ok(client_id) = std::env::var("AUTH0_CLIENT_ID") {
            config.provider = SsoProvider::Auth0;
            config.client_id = client_id;
            config.enabled = true;
            if let Ok(secret) = std::env::var("AUTH0_CLIENT_SECRET") {
                config.client_secret = secret;
            }
            if let Ok(domain) = std::env::var("AUTH0_DOMAIN") {
                config.auth_url = format!("https://{}/authorize", domain);
                config.token_url = format!("https://{}/oauth/token", domain);
                config.userinfo_url = Some(format!("https://{}/userinfo", domain));
            }
        }

        // Generic OIDC overrides
        if let Ok(client_id) = std::env::var("SSO_CLIENT_ID") {
            config.client_id = client_id;
            config.enabled = true;
        }
        if let Ok(secret) = std::env::var("SSO_CLIENT_SECRET") {
            config.client_secret = secret;
        }
        if let Ok(url) = std::env::var("SSO_AUTH_URL") {
            config.auth_url = url;
        }
        if let Ok(url) = std::env::var("SSO_TOKEN_URL") {
            config.token_url = url;
        }
        if let Ok(url) = std::env::var("SSO_USERINFO_URL") {
            config.userinfo_url = Some(url);
        }
        if let Ok(url) = std::env::var("SSO_ISSUER_URL") {
            config.issuer_url = Some(url);
        }
        if let Ok(uri) = std::env::var("SSO_REDIRECT_URI") {
            config.redirect_uri = uri;
        }
        if let Ok(claim) = std::env::var("SSO_USERNAME_CLAIM") {
            config.username_claim = claim;
        }
        if let Ok(claim) = std::env::var("SSO_EMAIL_CLAIM") {
            config.email_claim = claim;
        }

        config
    }

    /// Create preset for 1Password
    pub fn onepassword(client_id: &str, client_secret: &str) -> Self {
        Self {
            enabled: true,
            provider: SsoProvider::OnePassword,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://app.1password.com/oauth/authorize".to_string(),
            token_url: "https://app.1password.com/oauth/token".to_string(),
            ..Default::default()
        }
    }

    /// Create preset for Google
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            enabled: true,
            provider: SsoProvider::Google,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: Some("https://openidconnect.googleapis.com/v1/userinfo".to_string()),
            ..Default::default()
        }
    }

    /// Create preset for Microsoft
    pub fn microsoft(client_id: &str, client_secret: &str, tenant_id: &str) -> Self {
        Self {
            enabled: true,
            provider: SsoProvider::Microsoft,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/authorize",
                tenant_id
            ),
            token_url: format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                tenant_id
            ),
            userinfo_url: Some("https://graph.microsoft.com/oidc/userinfo".to_string()),
            ..Default::default()
        }
    }
}

/// SSO user info from OIDC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoUserInfo {
    /// Subject (unique user ID from provider)
    pub sub: String,
    /// Username (from configured claim)
    pub username: String,
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub name: Option<String>,
    /// Email verified flag
    pub email_verified: Option<bool>,
    /// Raw claims from provider
    pub claims: HashMap<String, serde_json::Value>,
}

/// App password for mail clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppPassword {
    /// Unique ID
    pub id: String,
    /// Hashed password
    pub password_hash: String,
    /// Display name/label
    pub label: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
    /// Expires at (optional)
    pub expires_at: Option<DateTime<Utc>>,
    /// Allowed protocols (empty = all)
    pub allowed_protocols: Vec<String>,
}

/// SSO session/token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    /// Access token
    pub access_token: String,
    /// Refresh token (optional)
    pub refresh_token: Option<String>,
    /// Token expiration
    pub expires_at: Option<DateTime<Utc>>,
    /// User info
    pub user_info: SsoUserInfo,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// Pending authorization state
#[derive(Debug, Clone)]
pub struct PendingAuth {
    /// CSRF token
    pub csrf_token: String,
    /// PKCE verifier
    pub pkce_verifier: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
}

/// OAuth2 token response
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// SSO authentication result
#[derive(Debug, Clone)]
pub enum SsoAuthResult {
    /// Success with user info
    Success(SsoUserInfo),
    /// Invalid token
    InvalidToken,
    /// Token expired
    TokenExpired,
    /// Provider error
    ProviderError(String),
    /// SSO not enabled
    NotEnabled,
}

/// User's SSO data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserSsoData {
    /// SSO provider subject ID
    pub provider_sub: Option<String>,
    /// SSO provider type
    pub provider: Option<String>,
    /// App passwords
    pub app_passwords: Vec<AppPassword>,
    /// Last SSO login
    pub last_sso_login: Option<DateTime<Utc>>,
}

/// SSO Manager
#[derive(Debug)]
pub struct SsoManager {
    /// Configuration
    config: SsoConfig,
    /// HTTP client
    http_client: HttpClient,
    /// Pending authorizations (CSRF token -> state)
    pending_auth: Arc<RwLock<HashMap<String, PendingAuth>>>,
    /// User SSO data
    user_data: Arc<RwLock<HashMap<String, UserSsoData>>>,
    /// Data directory
    data_dir: PathBuf,
}

impl SsoManager {
    /// Create a new SSO manager
    pub fn new(config: SsoConfig, data_dir: PathBuf) -> Self {
        Self {
            config,
            http_client: HttpClient::new(),
            pending_auth: Arc::new(RwLock::new(HashMap::new())),
            user_data: Arc::new(RwLock::new(HashMap::new())),
            data_dir,
        }
    }

    /// Create from environment
    pub fn from_env(data_dir: PathBuf) -> Self {
        Self::new(SsoConfig::from_env(), data_dir)
    }

    /// Check if SSO is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.client_id.is_empty()
    }

    /// Get SSO status
    pub fn status(&self) -> SsoStatus {
        SsoStatus {
            enabled: self.is_enabled(),
            provider: self.config.provider.clone(),
            provider_name: self.config.provider.display_name().to_string(),
            allow_app_passwords: self.config.allow_app_passwords,
        }
    }

    /// Load user SSO data from disk
    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("sso_data.json");
        if !path.exists() {
            return Ok(());
        }

        let data = tokio::fs::read_to_string(&path).await?;
        let user_data: HashMap<String, UserSsoData> = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        *self.user_data.write().await = user_data;
        Ok(())
    }

    /// Save user SSO data to disk
    pub async fn save(&self) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("sso_data.json");

        let data = serde_json::to_string_pretty(&*self.user_data.read().await)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        tokio::fs::write(&path, data).await
    }

    /// Start OAuth2 authorization flow
    pub async fn start_auth(&self) -> Result<(String, String), String> {
        if !self.is_enabled() {
            return Err("SSO is not enabled".to_string());
        }

        // Generate CSRF state and PKCE verifier
        let state = generate_random_string(32);
        let pkce_verifier = generate_random_string(64);
        let pkce_challenge = generate_pkce_challenge(&pkce_verifier);

        // Build authorization URL
        let scopes = self.config.scopes.join(" ");
        let auth_url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.config.auth_url,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(&scopes),
            urlencoding::encode(&state),
            urlencoding::encode(&pkce_challenge),
        );

        // Store pending auth state
        let pending = PendingAuth {
            csrf_token: state.clone(),
            pkce_verifier,
            created_at: Utc::now(),
        };

        self.pending_auth
            .write()
            .await
            .insert(state.clone(), pending);

        // Clean up old pending auths (older than 10 minutes)
        self.cleanup_pending_auth().await;

        Ok((auth_url, state))
    }

    /// Complete OAuth2 authorization flow
    pub async fn complete_auth(&self, code: &str, state: &str) -> Result<SsoUserInfo, String> {
        if !self.is_enabled() {
            return Err("SSO is not enabled".to_string());
        }

        // Verify CSRF state
        let pending = self
            .pending_auth
            .write()
            .await
            .remove(state)
            .ok_or_else(|| "Invalid or expired authorization state".to_string())?;

        // Check if expired (10 minute window)
        if Utc::now() - pending.created_at > Duration::minutes(10) {
            return Err("Authorization expired".to_string());
        }

        // Exchange code for token
        let token_response = self
            .http_client
            .post(&self.config.token_url)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.config.redirect_uri),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
                ("code_verifier", &pending.pkce_verifier),
            ])
            .send()
            .await
            .map_err(|e| format!("Token request failed: {}", e))?;

        if !token_response.status().is_success() {
            let error_text = token_response.text().await.unwrap_or_default();
            return Err(format!("Token exchange failed: {}", error_text));
        }

        let token_data: TokenResponse = token_response
            .json()
            .await
            .map_err(|e| format!("Failed to parse token response: {}", e))?;

        // Get user info
        let user_info = self.fetch_user_info(&token_data.access_token).await?;

        // Store user SSO data
        let mut data = self.user_data.write().await;
        let user_data = data.entry(user_info.username.clone()).or_default();
        user_data.provider_sub = Some(user_info.sub.clone());
        user_data.provider = Some(self.config.provider.display_name().to_string());
        user_data.last_sso_login = Some(Utc::now());
        drop(data);

        let _ = self.save().await;

        tracing::info!("SSO authentication successful for {}", user_info.username);
        Ok(user_info)
    }

    /// Fetch user info from provider
    async fn fetch_user_info(&self, access_token: &str) -> Result<SsoUserInfo, String> {
        let userinfo_url = self
            .config
            .userinfo_url
            .as_ref()
            .ok_or_else(|| "UserInfo endpoint not configured".to_string())?;

        let response = self
            .http_client
            .get(userinfo_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| format!("UserInfo request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("UserInfo request failed: {}", response.status()));
        }

        let claims: HashMap<String, serde_json::Value> = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse UserInfo: {}", e))?;

        // Extract fields based on configured claims
        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let username = claims
            .get(&self.config.username_claim)
            .and_then(|v| v.as_str())
            .or_else(|| claims.get("email").and_then(|v| v.as_str()))
            .unwrap_or(&sub)
            .to_string();

        // Extract local part from email for username
        let username = if username.contains('@') {
            username.split('@').next().unwrap_or(&username).to_string()
        } else {
            username
        };

        let email = claims
            .get(&self.config.email_claim)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let name = claims
            .get(&self.config.name_claim)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let email_verified = claims.get("email_verified").and_then(|v| v.as_bool());

        Ok(SsoUserInfo {
            sub,
            username,
            email,
            name,
            email_verified,
            claims,
        })
    }

    /// Generate an app password for a user
    pub async fn generate_app_password(
        &self,
        username: &str,
        label: &str,
        expires_days: Option<u32>,
    ) -> Result<String, String> {
        if !self.config.allow_app_passwords {
            return Err("App passwords are not enabled".to_string());
        }

        // Generate random password
        let password = generate_app_password(self.config.app_password_length);
        let password_hash = hash_app_password(&password)?;

        let app_password = AppPassword {
            id: uuid::Uuid::new_v4().to_string(),
            password_hash,
            label: label.to_string(),
            created_at: Utc::now(),
            last_used: None,
            expires_at: expires_days.map(|d| Utc::now() + Duration::days(d as i64)),
            allowed_protocols: vec![],
        };

        // Store app password
        let mut data = self.user_data.write().await;
        let user_data = data.entry(username.to_string()).or_default();
        user_data.app_passwords.push(app_password);
        drop(data);

        let _ = self.save().await;

        tracing::info!("Generated app password '{}' for {}", label, username);
        Ok(password)
    }

    /// Verify an app password
    pub async fn verify_app_password(
        &self,
        username: &str,
        password: &str,
        protocol: &str,
    ) -> bool {
        let mut data = self.user_data.write().await;

        if let Some(user_data) = data.get_mut(username) {
            for app_pw in &mut user_data.app_passwords {
                // Check expiration
                if let Some(expires_at) = app_pw.expires_at {
                    if Utc::now() > expires_at {
                        continue;
                    }
                }

                // Check protocol restrictions
                if !app_pw.allowed_protocols.is_empty()
                    && !app_pw.allowed_protocols.contains(&protocol.to_string())
                {
                    continue;
                }

                // Verify password
                if verify_app_password(password, &app_pw.password_hash) {
                    app_pw.last_used = Some(Utc::now());
                    drop(data);
                    let _ = self.save().await;
                    return true;
                }
            }
        }

        false
    }

    /// List app passwords for a user
    pub async fn list_app_passwords(&self, username: &str) -> Vec<AppPasswordInfo> {
        let data = self.user_data.read().await;

        data.get(username)
            .map(|user_data| {
                user_data
                    .app_passwords
                    .iter()
                    .map(|ap| AppPasswordInfo {
                        id: ap.id.clone(),
                        label: ap.label.clone(),
                        created_at: ap.created_at,
                        last_used: ap.last_used,
                        expires_at: ap.expires_at,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Revoke an app password
    pub async fn revoke_app_password(&self, username: &str, password_id: &str) -> bool {
        let mut data = self.user_data.write().await;

        if let Some(user_data) = data.get_mut(username) {
            let initial_len = user_data.app_passwords.len();
            user_data.app_passwords.retain(|ap| ap.id != password_id);

            if user_data.app_passwords.len() < initial_len {
                drop(data);
                let _ = self.save().await;
                return true;
            }
        }

        false
    }

    /// Clean up expired pending authorizations
    async fn cleanup_pending_auth(&self) {
        let cutoff = Utc::now() - Duration::minutes(10);
        let mut pending = self.pending_auth.write().await;
        pending.retain(|_, v| v.created_at > cutoff);
    }

    /// Get user's SSO data
    pub async fn get_user_data(&self, username: &str) -> Option<UserSsoData> {
        self.user_data.read().await.get(username).cloned()
    }
}

/// App password info (without sensitive data)
#[derive(Debug, Clone, Serialize)]
pub struct AppPasswordInfo {
    pub id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// SSO status
#[derive(Debug, Clone, serde::Serialize)]
pub struct SsoStatus {
    pub enabled: bool,
    pub provider: SsoProvider,
    pub provider_name: String,
    pub allow_app_passwords: bool,
}

/// Generate a random string of specified length
fn generate_random_string(length: usize) -> String {
    use rand::Rng;
    let mut rng = rand::rng();

    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();

    (0..length)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect()
}

/// Generate PKCE code challenge from verifier
fn generate_pkce_challenge(verifier: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();

    // Base64 URL-safe encoding without padding
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
}

/// Generate a random app password
fn generate_app_password(length: usize) -> String {
    use rand::Rng;
    let mut rng = rand::rng();

    // Use a character set that's easy to type and unambiguous
    let chars: Vec<char> = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
        .chars()
        .collect();

    // Format as xxxx-xxxx-xxxx-xxxx for readability
    let raw: String = (0..length)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect();

    // Insert dashes every 4 characters
    raw.chars()
        .enumerate()
        .flat_map(|(i, c)| {
            if i > 0 && i % 4 == 0 {
                vec!['-', c]
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Hash an app password using Argon2
fn hash_app_password(password: &str) -> Result<String, String> {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString};

    // Use password_hash's own RNG to avoid version conflicts
    let salt = SaltString::generate(&mut password_hash::rand_core::OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Failed to hash password: {}", e))
}

/// Verify an app password
fn verify_app_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordVerifier, password_hash::PasswordHash};

    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = SsoConfig::default();
        assert!(!config.enabled);
        assert!(config.allow_app_passwords);
        assert_eq!(config.username_claim, "preferred_username");
    }

    #[test]
    fn test_app_password_generation() {
        let password = generate_app_password(24);
        // 24 chars + 5 dashes = 29 total
        assert_eq!(password.len(), 29);
        assert!(password.contains('-'));
    }

    #[test]
    fn test_app_password_hash_verify() {
        let password = "test-pass-word-1234";
        let hash = hash_app_password(password).unwrap();

        assert!(verify_app_password(password, &hash));
        assert!(!verify_app_password("wrong-password", &hash));
    }

    #[test]
    fn test_provider_presets() {
        let google = SsoConfig::google("client_id", "secret");
        assert_eq!(google.provider, SsoProvider::Google);
        assert!(google.auth_url.contains("google"));

        let microsoft = SsoConfig::microsoft("client_id", "secret", "tenant");
        assert_eq!(microsoft.provider, SsoProvider::Microsoft);
        assert!(microsoft.auth_url.contains("microsoftonline"));
    }

    #[tokio::test]
    async fn test_disabled_sso() {
        let manager = SsoManager::new(SsoConfig::default(), PathBuf::from("/tmp"));
        assert!(!manager.is_enabled());

        let result = manager.start_auth().await;
        assert!(result.is_err());
    }
}
