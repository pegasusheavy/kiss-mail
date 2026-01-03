//! LDAP integration module.
//!
//! Provides LDAP authentication and directory services:
//! - User authentication via LDAP bind
//! - User/group synchronization from LDAP directory
//! - Fallback to local authentication when LDAP unavailable

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// LDAP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., "ldap://localhost:389" or "ldaps://ldap.example.com:636")
    pub url: String,
    /// Base DN for searches (e.g., "dc=example,dc=com")
    pub base_dn: String,
    /// Bind DN for directory searches (optional, for anonymous bind leave empty)
    pub bind_dn: Option<String>,
    /// Bind password
    pub bind_password: Option<String>,
    /// User search filter template (use {username} as placeholder)
    /// e.g., "(&(objectClass=person)(uid={username}))"
    pub user_filter: String,
    /// User DN template for direct bind (use {username} as placeholder)
    /// e.g., "uid={username},ou=users,dc=example,dc=com"
    pub user_dn_template: Option<String>,
    /// Attribute containing the username
    pub username_attr: String,
    /// Attribute containing the email
    pub email_attr: String,
    /// Attribute containing the display name
    pub display_name_attr: String,
    /// Group search base DN (optional)
    pub group_base_dn: Option<String>,
    /// Group search filter template
    pub group_filter: String,
    /// Group member attribute
    pub group_member_attr: String,
    /// Connection timeout in seconds
    pub timeout_seconds: u64,
    /// Enable TLS/SSL
    pub use_tls: bool,
    /// Enable StartTLS
    pub use_starttls: bool,
    /// Whether LDAP is enabled
    pub enabled: bool,
    /// Fallback to local auth if LDAP fails
    pub fallback_to_local: bool,
}

impl Default for LdapConfig {
    fn default() -> Self {
        Self {
            url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: None,
            bind_password: None,
            user_filter: "(&(objectClass=inetOrgPerson)(uid={username}))".to_string(),
            user_dn_template: Some("uid={username},ou=users,dc=example,dc=com".to_string()),
            username_attr: "uid".to_string(),
            email_attr: "mail".to_string(),
            display_name_attr: "cn".to_string(),
            group_base_dn: None,
            group_filter: "(&(objectClass=groupOfNames)(member={user_dn}))".to_string(),
            group_member_attr: "member".to_string(),
            timeout_seconds: 10,
            use_tls: false,
            use_starttls: false,
            enabled: false,
            fallback_to_local: true,
        }
    }
}

impl LdapConfig {
    /// Create config from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(url) = std::env::var("LDAP_URL") {
            config.url = url;
            config.enabled = true;
        }

        if let Ok(base_dn) = std::env::var("LDAP_BASE_DN") {
            config.base_dn = base_dn;
        }

        if let Ok(bind_dn) = std::env::var("LDAP_BIND_DN") {
            config.bind_dn = Some(bind_dn);
        }

        if let Ok(bind_password) = std::env::var("LDAP_BIND_PASSWORD") {
            config.bind_password = Some(bind_password);
        }

        if let Ok(user_filter) = std::env::var("LDAP_USER_FILTER") {
            config.user_filter = user_filter;
        }

        if let Ok(user_dn_template) = std::env::var("LDAP_USER_DN_TEMPLATE") {
            config.user_dn_template = Some(user_dn_template);
        }

        if let Ok(username_attr) = std::env::var("LDAP_USERNAME_ATTR") {
            config.username_attr = username_attr;
        }

        if let Ok(email_attr) = std::env::var("LDAP_EMAIL_ATTR") {
            config.email_attr = email_attr;
        }

        if let Ok(display_name_attr) = std::env::var("LDAP_DISPLAY_NAME_ATTR") {
            config.display_name_attr = display_name_attr;
        }

        if let Ok(group_base_dn) = std::env::var("LDAP_GROUP_BASE_DN") {
            config.group_base_dn = Some(group_base_dn);
        }

        if let Ok(group_filter) = std::env::var("LDAP_GROUP_FILTER") {
            config.group_filter = group_filter;
        }

        if let Ok(val) = std::env::var("LDAP_USE_TLS") {
            config.use_tls = val == "1" || val.to_lowercase() == "true";
        }

        if let Ok(val) = std::env::var("LDAP_USE_STARTTLS") {
            config.use_starttls = val == "1" || val.to_lowercase() == "true";
        }

        if let Ok(val) = std::env::var("LDAP_FALLBACK_LOCAL") {
            config.fallback_to_local = val != "0" && val.to_lowercase() != "false";
        }

        if let Ok(timeout) = std::env::var("LDAP_TIMEOUT") {
            if let Ok(secs) = timeout.parse() {
                config.timeout_seconds = secs;
            }
        }

        config
    }
}

/// LDAP user information
#[derive(Debug, Clone)]
pub struct LdapUser {
    /// Distinguished Name
    pub dn: String,
    /// Username
    pub username: String,
    /// Email address
    pub email: Option<String>,
    /// Display name
    pub display_name: Option<String>,
    /// Group memberships
    pub groups: Vec<String>,
    /// Additional attributes
    pub attributes: HashMap<String, Vec<String>>,
}

/// LDAP group information
#[derive(Debug, Clone)]
pub struct LdapGroup {
    /// Distinguished Name
    pub dn: String,
    /// Group name (CN)
    pub name: String,
    /// Group members (DNs)
    pub members: Vec<String>,
}

/// LDAP authentication result
#[derive(Debug, Clone)]
pub enum LdapAuthResult {
    /// Successfully authenticated
    Success(LdapUser),
    /// Invalid credentials
    InvalidCredentials,
    /// User not found
    UserNotFound,
    /// LDAP error (connection, timeout, etc.)
    Error(String),
    /// LDAP not enabled, use local auth
    NotEnabled,
}

/// LDAP client for authentication and directory services
#[derive(Debug)]
pub struct LdapClient {
    /// LDAP configuration
    config: LdapConfig,
    /// Connection pool (simple: just track if we have a working connection)
    last_error: Arc<RwLock<Option<String>>>,
}

impl LdapClient {
    /// Create a new LDAP client
    pub fn new(config: LdapConfig) -> Self {
        Self {
            config,
            last_error: Arc::new(RwLock::new(None)),
        }
    }

    /// Create from environment variables
    pub fn from_env() -> Self {
        Self::new(LdapConfig::from_env())
    }

    /// Check if LDAP is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if fallback to local auth is enabled
    pub fn fallback_enabled(&self) -> bool {
        self.config.fallback_to_local
    }

    /// Get the last error message
    pub async fn last_error(&self) -> Option<String> {
        self.last_error.read().await.clone()
    }

    /// Get LDAP status
    pub fn status(&self) -> LdapStatus {
        LdapStatus {
            enabled: self.config.enabled,
            url: self.config.url.clone(),
            base_dn: self.config.base_dn.clone(),
            use_tls: self.config.use_tls,
            use_starttls: self.config.use_starttls,
            fallback_to_local: self.config.fallback_to_local,
        }
    }

    /// Connect to LDAP server
    async fn connect(&self) -> Result<Ldap, String> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(self.config.timeout_seconds));

        let (conn, ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| format!("LDAP connection failed: {}", e))?;

        // Drive the connection in background
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                tracing::error!("LDAP connection error: {}", e);
            }
        });

        // Note: For TLS, use ldaps:// URL. StartTLS would require additional setup.
        // The ldap3 crate handles TLS automatically when using ldaps:// URLs.

        Ok(ldap)
    }

    /// Bind with service account (for searches)
    async fn bind_service(&self, ldap: &mut Ldap) -> Result<(), String> {
        if let (Some(bind_dn), Some(bind_password)) =
            (&self.config.bind_dn, &self.config.bind_password)
        {
            ldap.simple_bind(bind_dn, bind_password)
                .await
                .map_err(|e| format!("LDAP bind failed: {}", e))?
                .success()
                .map_err(|e| format!("LDAP bind rejected: {}", e))?;
        }
        Ok(())
    }

    /// Authenticate a user with username and password
    pub async fn authenticate(&self, username: &str, password: &str) -> LdapAuthResult {
        if !self.config.enabled {
            return LdapAuthResult::NotEnabled;
        }

        // Clear previous error
        *self.last_error.write().await = None;

        // Try direct bind first if user_dn_template is set
        if let Some(ref template) = self.config.user_dn_template {
            let user_dn = template.replace("{username}", username);
            match self.authenticate_direct_bind(&user_dn, password).await {
                Ok(true) => {
                    // Fetch user details
                    match self.get_user(username).await {
                        Ok(Some(user)) => return LdapAuthResult::Success(user),
                        Ok(None) => {
                            // User authenticated but not found in search
                            // Create minimal user info
                            return LdapAuthResult::Success(LdapUser {
                                dn: user_dn,
                                username: username.to_string(),
                                email: None,
                                display_name: None,
                                groups: vec![],
                                attributes: HashMap::new(),
                            });
                        }
                        Err(e) => {
                            tracing::warn!("LDAP user lookup failed after auth: {}", e);
                            return LdapAuthResult::Success(LdapUser {
                                dn: user_dn,
                                username: username.to_string(),
                                email: None,
                                display_name: None,
                                groups: vec![],
                                attributes: HashMap::new(),
                            });
                        }
                    }
                }
                Ok(false) => return LdapAuthResult::InvalidCredentials,
                Err(e) => {
                    *self.last_error.write().await = Some(e.clone());
                    return LdapAuthResult::Error(e);
                }
            }
        }

        // Search-then-bind approach
        match self.search_and_bind_authenticate(username, password).await {
            Ok(Some(user)) => LdapAuthResult::Success(user),
            Ok(None) => LdapAuthResult::InvalidCredentials,
            Err(e) => {
                *self.last_error.write().await = Some(e.clone());
                if e.contains("not found") {
                    LdapAuthResult::UserNotFound
                } else {
                    LdapAuthResult::Error(e)
                }
            }
        }
    }

    /// Direct bind authentication
    async fn authenticate_direct_bind(&self, user_dn: &str, password: &str) -> Result<bool, String> {
        let mut ldap = self.connect().await?;

        let result = ldap
            .simple_bind(user_dn, password)
            .await
            .map_err(|e| format!("LDAP bind error: {}", e))?;

        let _ = ldap.unbind().await;

        match result.rc {
            0 => Ok(true),
            49 => Ok(false), // Invalid credentials
            _ => Err(format!("LDAP bind failed with code {}: {}", result.rc, result.text)),
        }
    }

    /// Search for user, then bind with their DN
    async fn search_and_bind_authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<LdapUser>, String> {
        let mut ldap = self.connect().await?;
        self.bind_service(&mut ldap).await?;

        // Search for user
        let filter = self.config.user_filter.replace("{username}", username);
        let attrs = vec![
            &self.config.username_attr as &str,
            &self.config.email_attr,
            &self.config.display_name_attr,
            "memberOf",
        ];

        let (rs, _) = ldap
            .search(&self.config.base_dn, Scope::Subtree, &filter, attrs)
            .await
            .map_err(|e| format!("LDAP search failed: {}", e))?
            .success()
            .map_err(|e| format!("LDAP search error: {}", e))?;

        let _ = ldap.unbind().await;

        if rs.is_empty() {
            return Err(format!("User '{}' not found in LDAP", username));
        }

        let entry = SearchEntry::construct(rs.into_iter().next().unwrap());
        let user_dn = entry.dn.clone();

        // Now bind as the user to verify password
        let auth_result = self.authenticate_direct_bind(&user_dn, password).await?;

        if !auth_result {
            return Ok(None);
        }

        // Build user info
        let user = self.entry_to_user(entry);
        Ok(Some(user))
    }

    /// Get user information by username
    pub async fn get_user(&self, username: &str) -> Result<Option<LdapUser>, String> {
        if !self.config.enabled {
            return Ok(None);
        }

        let mut ldap = self.connect().await?;
        self.bind_service(&mut ldap).await?;

        let filter = self.config.user_filter.replace("{username}", username);
        let attrs = vec![
            &self.config.username_attr as &str,
            &self.config.email_attr,
            &self.config.display_name_attr,
            "memberOf",
        ];

        let (rs, _) = ldap
            .search(&self.config.base_dn, Scope::Subtree, &filter, attrs)
            .await
            .map_err(|e| format!("LDAP search failed: {}", e))?
            .success()
            .map_err(|e| format!("LDAP search error: {}", e))?;

        let _ = ldap.unbind().await;

        if rs.is_empty() {
            return Ok(None);
        }

        let entry = SearchEntry::construct(rs.into_iter().next().unwrap());
        Ok(Some(self.entry_to_user(entry)))
    }

    /// Search for users matching a filter
    pub async fn search_users(&self, filter: &str) -> Result<Vec<LdapUser>, String> {
        if !self.config.enabled {
            return Ok(vec![]);
        }

        let mut ldap = self.connect().await?;
        self.bind_service(&mut ldap).await?;

        let attrs = vec![
            &self.config.username_attr as &str,
            &self.config.email_attr,
            &self.config.display_name_attr,
            "memberOf",
        ];

        let (rs, _) = ldap
            .search(&self.config.base_dn, Scope::Subtree, filter, attrs)
            .await
            .map_err(|e| format!("LDAP search failed: {}", e))?
            .success()
            .map_err(|e| format!("LDAP search error: {}", e))?;

        let _ = ldap.unbind().await;

        let users = rs
            .into_iter()
            .map(|entry| self.entry_to_user(SearchEntry::construct(entry)))
            .collect();

        Ok(users)
    }

    /// Get groups for a user
    pub async fn get_user_groups(&self, user_dn: &str) -> Result<Vec<LdapGroup>, String> {
        if !self.config.enabled {
            return Ok(vec![]);
        }

        let group_base = self
            .config
            .group_base_dn
            .as_ref()
            .unwrap_or(&self.config.base_dn);

        let mut ldap = self.connect().await?;
        self.bind_service(&mut ldap).await?;

        let filter = self.config.group_filter.replace("{user_dn}", user_dn);
        let attrs = vec!["cn", &self.config.group_member_attr as &str];

        let (rs, _) = ldap
            .search(group_base, Scope::Subtree, &filter, attrs)
            .await
            .map_err(|e| format!("LDAP group search failed: {}", e))?
            .success()
            .map_err(|e| format!("LDAP group search error: {}", e))?;

        let _ = ldap.unbind().await;

        let groups = rs
            .into_iter()
            .map(|entry| {
                let se = SearchEntry::construct(entry);
                LdapGroup {
                    dn: se.dn.clone(),
                    name: se
                        .attrs
                        .get("cn")
                        .and_then(|v| v.first())
                        .cloned()
                        .unwrap_or_default(),
                    members: se
                        .attrs
                        .get(&self.config.group_member_attr)
                        .cloned()
                        .unwrap_or_default(),
                }
            })
            .collect();

        Ok(groups)
    }

    /// Sync all users from LDAP
    pub async fn sync_all_users(&self) -> Result<Vec<LdapUser>, String> {
        if !self.config.enabled {
            return Ok(vec![]);
        }

        // Use a broad filter to get all users
        let filter = self
            .config
            .user_filter
            .replace("{username}", "*")
            .replace("(uid=*)", "(objectClass=inetOrgPerson)");

        self.search_users(&filter).await
    }

    /// Convert LDAP entry to LdapUser
    fn entry_to_user(&self, entry: SearchEntry) -> LdapUser {
        let username = entry
            .attrs
            .get(&self.config.username_attr)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default();

        let email = entry
            .attrs
            .get(&self.config.email_attr)
            .and_then(|v| v.first())
            .cloned();

        let display_name = entry
            .attrs
            .get(&self.config.display_name_attr)
            .and_then(|v| v.first())
            .cloned();

        let groups = entry
            .attrs
            .get("memberOf")
            .cloned()
            .unwrap_or_default();

        LdapUser {
            dn: entry.dn,
            username,
            email,
            display_name,
            groups,
            attributes: entry.attrs,
        }
    }

    /// Test LDAP connection
    pub async fn test_connection(&self) -> Result<String, String> {
        if !self.config.enabled {
            return Err("LDAP is not enabled".to_string());
        }

        let mut ldap = self.connect().await?;
        self.bind_service(&mut ldap).await?;

        // Try to get root DSE
        let (rs, _) = ldap
            .search("", Scope::Base, "(objectClass=*)", vec!["namingContexts", "supportedLDAPVersion"])
            .await
            .map_err(|e| format!("LDAP search failed: {}", e))?
            .success()
            .map_err(|e| format!("LDAP search error: {}", e))?;

        let _ = ldap.unbind().await;

        if let Some(entry) = rs.into_iter().next() {
            let se = SearchEntry::construct(entry);
            let versions = se
                .attrs
                .get("supportedLDAPVersion")
                .map(|v| v.join(", "))
                .unwrap_or_else(|| "unknown".to_string());
            Ok(format!("Connected to LDAP server (versions: {})", versions))
        } else {
            Ok("Connected to LDAP server".to_string())
        }
    }
}

/// LDAP status information
#[derive(Debug, Clone, serde::Serialize)]
pub struct LdapStatus {
    pub enabled: bool,
    pub url: String,
    pub base_dn: String,
    pub use_tls: bool,
    pub use_starttls: bool,
    pub fallback_to_local: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = LdapConfig::default();
        assert!(!config.enabled);
        assert!(config.fallback_to_local);
        assert_eq!(config.username_attr, "uid");
        assert_eq!(config.email_attr, "mail");
    }

    #[test]
    fn test_user_filter_replacement() {
        let config = LdapConfig::default();
        let filter = config.user_filter.replace("{username}", "testuser");
        assert!(filter.contains("testuser"));
        assert!(!filter.contains("{username}"));
    }

    #[test]
    fn test_user_dn_template() {
        let config = LdapConfig::default();
        let template = config.user_dn_template.unwrap();
        let dn = template.replace("{username}", "alice");
        assert_eq!(dn, "uid=alice,ou=users,dc=example,dc=com");
    }

    #[tokio::test]
    async fn test_disabled_ldap() {
        let client = LdapClient::new(LdapConfig::default());
        assert!(!client.is_enabled());

        let result = client.authenticate("user", "pass").await;
        assert!(matches!(result, LdapAuthResult::NotEnabled));
    }
}
