//! Remote Admin API for KISS Mail Server.
//!
//! Provides a REST API for remote server administration.
//! Secured via API key or admin credentials.

use axum::{
    extract::{Path, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::antispam::AntiSpam;
use crate::antivirus::AntiVirus;
use crate::groups::GroupManager;
use crate::ldap::LdapClient;
use crate::sso::SsoManager;
use crate::storage::Storage;
use crate::users::{AccountStatus, UserAccount, UserManager, UserRole};

/// Create a synthetic API admin actor for operations that require one
fn api_admin_actor() -> UserAccount {
    use crate::users::UserSettings;
    UserAccount {
        username: "api-admin".to_string(),
        password_hash: String::new(),
        domain: "localhost".to_string(),
        role: UserRole::SuperAdmin,
        status: AccountStatus::Active,
        quota: Default::default(),
        settings: UserSettings {
            display_name: Some("API Administrator".to_string()),
            ..Default::default()
        },
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        last_login: None,
        failed_login_attempts: 0,
        last_failed_login: None,
        login_history: vec![],
        password_change_required: false,
        password_changed_at: chrono::Utc::now(),
        allowed_ips: vec![],
        admin_notes: None,
    }
}

/// Admin API configuration
#[derive(Debug, Clone)]
pub struct AdminApiConfig {
    /// API key for authentication (optional, can use admin credentials)
    pub api_key: Option<String>,
    /// Port to listen on
    pub port: u16,
    /// Bind address
    pub bind_address: String,
    /// Enable API (default: true if api_key is set)
    pub enabled: bool,
}

impl Default for AdminApiConfig {
    fn default() -> Self {
        Self {
            api_key: std::env::var("KISS_MAIL_API_KEY").ok(),
            port: std::env::var("KISS_MAIL_API_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(8025),
            bind_address: std::env::var("KISS_MAIL_API_BIND")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            enabled: std::env::var("KISS_MAIL_API_KEY").is_ok()
                || std::env::var("KISS_MAIL_API_ENABLED").map(|v| v == "true" || v == "1").unwrap_or(false),
        }
    }
}

impl AdminApiConfig {
    pub fn from_env() -> Self {
        Self::default()
    }
}

/// Shared state for API handlers
#[derive(Clone)]
pub struct ApiState {
    pub user_manager: Arc<UserManager>,
    pub group_manager: Arc<GroupManager>,
    pub storage: Arc<Storage>,
    pub antispam: Arc<AntiSpam>,
    pub antivirus: Arc<AntiVirus>,
    pub ldap_client: Arc<LdapClient>,
    pub sso_manager: Arc<SsoManager>,
    pub config: AdminApiConfig,
    pub domain: String,
    pub tokens: TokenStore,
}

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
}

impl ApiResponse<()> {
    pub fn error(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub status: String,
    pub display_name: Option<String>,
    pub created_at: String,
    pub last_login: Option<String>,
    pub login_count: u32,
}

impl From<&UserAccount> for UserInfo {
    fn from(u: &UserAccount) -> Self {
        Self {
            username: u.username.clone(),
            role: format!("{:?}", u.role),
            status: format!("{:?}", u.status),
            display_name: u.settings.display_name.clone(),
            created_at: u.created_at.to_rfc3339(),
            last_login: u.last_login.map(|t| t.to_rfc3339()),
            login_count: u.login_history.len() as u32,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub email: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub members: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupMemberRequest {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupInfo {
    pub name: String,
    pub email: String,
    pub description: Option<String>,
    pub members: Vec<String>,
    pub managers: Vec<String>,
    pub owner: String,
    pub active: bool,
}

#[derive(Debug, Deserialize)]
pub struct AppPasswordRequest {
    pub label: Option<String>,
    pub expires_days: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AppPasswordResponse {
    pub password: String,
    pub label: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStatus {
    pub version: String,
    pub uptime_seconds: u64,
    pub domain: String,
    pub users: usize,
    pub groups: usize,
    pub ldap_enabled: bool,
    pub sso_enabled: bool,
    pub sso_provider: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthResponse {
    pub token: String,
    pub expires_in: u64,
}

// ============================================================================
// Authentication Middleware
// ============================================================================

/// Authentication state stored in request extensions
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub username: String,
    pub is_admin: bool,
}

/// Active tokens (in-memory session store)
pub type TokenStore = Arc<RwLock<std::collections::HashMap<String, AuthUser>>>;

/// Extract auth info from request
async fn auth_middleware(
    State(state): State<ApiState>,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    // Check for API key
    if let Some(api_key) = &state.config.api_key {
        if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    if token == api_key {
                        req.extensions_mut().insert(AuthUser {
                            username: "api-key".to_string(),
                            is_admin: true,
                        });
                        return next.run(req).await;
                    }
                }
            }
        }
    }

    // Check for session token
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                if let Some(user) = state.tokens.read().await.get(token).cloned() {
                    req.extensions_mut().insert(user);
                    return next.run(req).await;
                }
            }
        }
    }

    // Check X-API-Key header
    if let Some(api_key) = &state.config.api_key {
        if let Some(key_header) = req.headers().get("X-API-Key") {
            if let Ok(key_str) = key_header.to_str() {
                if key_str == api_key {
                    req.extensions_mut().insert(AuthUser {
                        username: "api-key".to_string(),
                        is_admin: true,
                    });
                    return next.run(req).await;
                }
            }
        }
    }

    (StatusCode::UNAUTHORIZED, Json(ApiResponse::error("Unauthorized"))).into_response()
}

/// Require admin privileges
fn require_admin(auth: &AuthUser) -> Result<(), (StatusCode, Json<ApiResponse<()>>)> {
    if !auth.is_admin {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ApiResponse::error("Admin privileges required")),
        ));
    }
    Ok(())
}

// ============================================================================
// API Handlers
// ============================================================================

/// POST /api/auth/login - Login with admin credentials
async fn login(
    State(state): State<ApiState>,
    Json(req): Json<AuthRequest>,
) -> impl IntoResponse {
    // Authenticate user
    match state.user_manager.authenticate(&req.username, &req.password, "api", "admin-api").await {
        Ok(user) => {
            // Check if admin
            let is_admin = matches!(user.role, UserRole::Admin | UserRole::SuperAdmin);
            if !is_admin {
                return (
                    StatusCode::FORBIDDEN,
                    Json(ApiResponse::success(AuthResponse {
                        token: String::new(),
                        expires_in: 0,
                    })),
                );
            }

            // Generate token
            let token = generate_token();
            let auth_user = AuthUser {
                username: user.username.clone(),
                is_admin: true,
            };

            state.tokens.write().await.insert(token.clone(), auth_user);

            (
                StatusCode::OK,
                Json(ApiResponse::success(AuthResponse {
                    token,
                    expires_in: 3600,
                })),
            )
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(ApiResponse::success(AuthResponse {
                token: String::new(),
                expires_in: 0,
            })),
        ),
    }
}

/// POST /api/auth/logout - Logout
async fn logout(
    State(state): State<ApiState>,
    req: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                state.tokens.write().await.remove(token);
            }
        }
    }
    Json(ApiResponse::success(()))
}

/// GET /api/status - Server status
async fn get_status(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    let _ = auth; // Just verify authenticated
    
    let users = state.user_manager.list_users().await.len();
    let groups = state.group_manager.get_stats().await.total_groups;
    let ldap_status = state.ldap_client.status();
    let sso_status = state.sso_manager.status();

    Json(ApiResponse::success(ServerStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // Would need to track start time
        domain: state.domain.clone(),
        users,
        groups,
        ldap_enabled: ldap_status.enabled,
        sso_enabled: sso_status.enabled,
        sso_provider: if sso_status.enabled {
            Some(sso_status.provider_name)
        } else {
            None
        },
    }))
}

// ============================================================================
// User Management
// ============================================================================

/// GET /api/users - List all users
async fn list_users(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let users: Vec<UserInfo> = state
        .user_manager
        .list_users()
        .await
        .iter()
        .map(UserInfo::from)
        .collect();

    Json(ApiResponse::success(users)).into_response()
}

/// POST /api/users - Create user
async fn create_user(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(req): Json<CreateUserRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let role = match req.role.as_deref() {
        Some("admin") | Some("Admin") => UserRole::Admin,
        Some("superadmin") | Some("SuperAdmin") => UserRole::SuperAdmin,
        _ => UserRole::User,
    };

    match state.user_manager.create_user(&req.username, &req.password, Some(role)).await {
        Ok(mut user) => {
            // Update display name if provided
            if let Some(name) = req.display_name {
                let _ = state.user_manager.update_user(&req.username, |u| {
                    u.settings.display_name = Some(name.clone());
                }).await;
                user.settings.display_name = Some(name);
            }
            Json(ApiResponse::success(UserInfo::from(&user))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(format!("{:?}", e))),
        )
            .into_response(),
    }
}

/// GET /api/users/:username - Get user details
async fn get_user(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.user_manager.get_user(&username).await {
        Some(user) => Json(ApiResponse::success(UserInfo::from(&user))).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error("User not found")),
        )
            .into_response(),
    }
}

/// PUT /api/users/:username - Update user
async fn update_user(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    // Check user exists
    if state.user_manager.get_user(&username).await.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error("User not found")),
        )
            .into_response();
    }

    let admin_actor = api_admin_actor();

    // Update password
    if let Some(password) = req.password {
        if let Err(e) = state.user_manager.admin_reset_password(&username, &password, &admin_actor, false).await {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse::<()>::error(format!("{:?}", e))),
            )
                .into_response();
        }
    }

    // Update role
    if let Some(role_str) = req.role {
        let role = match role_str.to_lowercase().as_str() {
            "admin" => UserRole::Admin,
            "superadmin" => UserRole::SuperAdmin,
            _ => UserRole::User,
        };
        let _ = state.user_manager.set_role(&username, role, &admin_actor).await;
    }

    // Update display name
    if let Some(name) = req.display_name {
        let _ = state.user_manager.update_user(&username, |u| {
            u.settings.display_name = Some(name.clone());
        }).await;
    }

    // Update status
    if let Some(status_str) = req.status {
        let status = match status_str.to_lowercase().as_str() {
            "active" => Some(AccountStatus::Active),
            "suspended" => Some(AccountStatus::Suspended),
            "locked" => Some(AccountStatus::Locked),
            _ => None,
        };
        if let Some(s) = status {
            let _ = state.user_manager.set_status(&username, s, &admin_actor).await;
        }
    }

    match state.user_manager.get_user(&username).await {
        Some(user) => Json(ApiResponse::success(UserInfo::from(&user))).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse::<()>::error("Failed to retrieve updated user")),
        )
            .into_response(),
    }
}

/// DELETE /api/users/:username - Delete user
async fn delete_user(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let admin_actor = api_admin_actor();
    match state.user_manager.delete_user(&username, &admin_actor).await {
        Ok(_) => Json(ApiResponse::success(())).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(format!("{:?}", e))),
        )
            .into_response(),
    }
}

// ============================================================================
// Group Management
// ============================================================================

/// GET /api/groups - List all groups
async fn list_groups(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let groups: Vec<GroupInfo> = state
        .group_manager
        .list(Some("api-admin"), true)
        .await
        .into_iter()
        .map(|g| GroupInfo {
            name: g.name,
            email: g.email,
            description: if g.description.is_empty() { None } else { Some(g.description) },
            members: g.members.into_iter().collect(),
            managers: g.managers.into_iter().collect(),
            owner: g.owner,
            active: g.active,
        })
        .collect();

    Json(ApiResponse::success(groups)).into_response()
}

/// POST /api/groups - Create group
async fn create_group(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Json(req): Json<CreateGroupRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state
        .group_manager
        .create(&req.name, &req.email, &auth.username)
        .await
    {
        Ok(mut group) => {
            // Set description if provided
            if let Some(desc) = req.description {
                group.description = desc;
            }
            // Add members
            for member in req.members {
                group.add_member(member);
            }
            // Save updates
            let _ = state.group_manager.save().await;

            Json(ApiResponse::success(GroupInfo {
                name: group.name,
                email: group.email,
                description: if group.description.is_empty() { None } else { Some(group.description) },
                members: group.members.into_iter().collect(),
                managers: group.managers.into_iter().collect(),
                owner: group.owner,
                active: group.active,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(format!("{:?}", e))),
        )
            .into_response(),
    }
}

/// GET /api/groups/:name - Get group details
async fn get_group(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.group_manager.get(&name).await {
        Some(group) => Json(ApiResponse::success(GroupInfo {
            name: group.name,
            email: group.email,
            description: if group.description.is_empty() { None } else { Some(group.description) },
            members: group.members.into_iter().collect(),
            managers: group.managers.into_iter().collect(),
            owner: group.owner,
            active: group.active,
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error("Group not found")),
        )
            .into_response(),
    }
}

/// DELETE /api/groups/:name - Delete group
async fn delete_group(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.group_manager.delete(&name, "api-admin").await {
        Ok(_) => Json(ApiResponse::success(())).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(format!("{:?}", e))),
        )
            .into_response(),
    }
}

/// POST /api/groups/:name/members - Add member to group
async fn add_group_member(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(name): Path<String>,
    Json(req): Json<GroupMemberRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.group_manager.add_member(&name, &req.username, "api-admin").await {
        Ok(_) => Json(ApiResponse::success(())).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(format!("{:?}", e))),
        )
            .into_response(),
    }
}

/// DELETE /api/groups/:name/members/:username - Remove member from group
async fn remove_group_member(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path((name, username)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.group_manager.remove_member(&name, &username, "api-admin").await {
        Ok(_) => Json(ApiResponse::success(())).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(format!("{:?}", e))),
        )
            .into_response(),
    }
}

// ============================================================================
// SSO / App Passwords
// ============================================================================

/// GET /api/users/:username/app-passwords - List app passwords
async fn list_app_passwords(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let passwords = state.sso_manager.list_app_passwords(&username).await;
    Json(ApiResponse::success(passwords)).into_response()
}

/// POST /api/users/:username/app-passwords - Generate app password
async fn create_app_password(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path(username): Path<String>,
    Json(req): Json<AppPasswordRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let label = req.label.unwrap_or_else(|| "Remote CLI".to_string());
    
    match state
        .sso_manager
        .generate_app_password(&username, &label, req.expires_days)
        .await
    {
        Ok(password) => Json(ApiResponse::success(AppPasswordResponse {
            password,
            label,
            expires_at: None, // Would need to calculate from expires_days
        }))
        .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(e)),
        )
            .into_response(),
    }
}

/// DELETE /api/users/:username/app-passwords/:id - Revoke app password
async fn revoke_app_password(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
    Path((username, id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    if state.sso_manager.revoke_app_password(&username, &id).await {
        Json(ApiResponse::success(())).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(ApiResponse::<()>::error("App password not found")),
        )
            .into_response()
    }
}

// ============================================================================
// LDAP
// ============================================================================

/// GET /api/ldap/status - Get LDAP status
async fn ldap_status(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let status = state.ldap_client.status();
    Json(ApiResponse::success(status)).into_response()
}

/// POST /api/ldap/test - Test LDAP connection
async fn ldap_test(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    match state.ldap_client.test_connection().await {
        Ok(msg) => Json(ApiResponse::success(msg)).into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(ApiResponse::<()>::error(e)),
        )
            .into_response(),
    }
}

// ============================================================================
// SSO Status
// ============================================================================

/// GET /api/sso/status - Get SSO status
async fn sso_status(
    State(state): State<ApiState>,
    axum::Extension(auth): axum::Extension<AuthUser>,
) -> impl IntoResponse {
    if let Err(e) = require_admin(&auth) {
        return e.into_response();
    }

    let status = state.sso_manager.status();
    Json(ApiResponse::success(status)).into_response()
}

// ============================================================================
// Router & Server
// ============================================================================

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    (0..64)
        .map(|_| chars[rng.random_range(0..chars.len())])
        .collect()
}

/// Create the admin API router
pub fn create_router(mut state: ApiState) -> Router {
    // Initialize tokens store
    state.tokens = Arc::new(RwLock::new(std::collections::HashMap::new()));

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .with_state(state.clone());

    // Protected routes (auth required)
    let protected_routes = Router::new()
        // Status
        .route("/api/status", get(get_status))
        // Users
        .route("/api/users", get(list_users).post(create_user))
        .route(
            "/api/users/:username",
            get(get_user).put(update_user).delete(delete_user),
        )
        // Groups
        .route("/api/groups", get(list_groups).post(create_group))
        .route("/api/groups/:name", get(get_group).delete(delete_group))
        .route("/api/groups/:name/members", post(add_group_member))
        .route(
            "/api/groups/:name/members/:username",
            delete(remove_group_member),
        )
        // App passwords
        .route(
            "/api/users/:username/app-passwords",
            get(list_app_passwords).post(create_app_password),
        )
        .route(
            "/api/users/:username/app-passwords/:id",
            delete(revoke_app_password),
        )
        // LDAP
        .route("/api/ldap/status", get(ldap_status))
        .route("/api/ldap/test", post(ldap_test))
        // SSO
        .route("/api/sso/status", get(sso_status))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);

    public_routes.merge(protected_routes)
}

/// Start the admin API server
pub async fn run_api_server(state: ApiState) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !state.config.enabled {
        tracing::info!("Admin API disabled (set KISS_MAIL_API_KEY to enable)");
        return Ok(());
    }

    let addr = format!("{}:{}", state.config.bind_address, state.config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Admin API listening on http://{}", addr);
    if state.config.api_key.is_some() {
        tracing::info!("Admin API: API key authentication enabled");
    }

    let router = create_router(state);
    axum::serve(listener, router).await?;

    Ok(())
}

// ============================================================================
// CLI Remote Client
// ============================================================================

/// Remote API client for CLI
pub struct RemoteClient {
    base_url: String,
    api_key: Option<String>,
    token: Option<String>,
    client: reqwest::Client,
}

impl RemoteClient {
    pub fn new(server: &str) -> Self {
        let base_url = if server.starts_with("http") {
            server.to_string()
        } else {
            format!("http://{}", server)
        };

        Self {
            base_url,
            api_key: None,
            token: None,
            client: reqwest::Client::new(),
        }
    }

    pub fn with_api_key(mut self, key: String) -> Self {
        self.api_key = Some(key);
        self
    }

    pub async fn login(&mut self, username: &str, password: &str) -> Result<(), String> {
        let resp = self
            .client
            .post(format!("{}/api/auth/login", self.base_url))
            .json(&AuthRequest {
                username: username.to_string(),
                password: password.to_string(),
            })
            .send()
            .await
            .map_err(|e| format!("Request failed: {}", e))?;

        let result: ApiResponse<AuthResponse> = resp
            .json()
            .await
            .map_err(|e| format!("Invalid response: {}", e))?;

        if result.success {
            if let Some(data) = result.data {
                self.token = Some(data.token);
                Ok(())
            } else {
                Err("No token in response".to_string())
            }
        } else {
            Err(result.error.unwrap_or_else(|| "Login failed".to_string()))
        }
    }

    fn auth_header(&self) -> Option<String> {
        if let Some(key) = &self.api_key {
            Some(format!("Bearer {}", key))
        } else if let Some(token) = &self.token {
            Some(format!("Bearer {}", token))
        } else {
            None
        }
    }

    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, String> {
        let mut req = self.client.get(format!("{}{}", self.base_url, path));
        
        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await.map_err(|e| format!("Request failed: {}", e))?;
        let result: ApiResponse<T> = resp
            .json()
            .await
            .map_err(|e| format!("Invalid response: {}", e))?;

        if result.success {
            result.data.ok_or_else(|| "No data in response".to_string())
        } else {
            Err(result.error.unwrap_or_else(|| "Request failed".to_string()))
        }
    }

    async fn post<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, String> {
        let mut req = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(body);

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await.map_err(|e| format!("Request failed: {}", e))?;
        let result: ApiResponse<T> = resp
            .json()
            .await
            .map_err(|e| format!("Invalid response: {}", e))?;

        if result.success {
            result.data.ok_or_else(|| "No data in response".to_string())
        } else {
            Err(result.error.unwrap_or_else(|| "Request failed".to_string()))
        }
    }

    async fn delete(&self, path: &str) -> Result<(), String> {
        let mut req = self.client.delete(format!("{}{}", self.base_url, path));

        if let Some(auth) = self.auth_header() {
            req = req.header("Authorization", auth);
        }

        let resp = req.send().await.map_err(|e| format!("Request failed: {}", e))?;
        let result: ApiResponse<()> = resp
            .json()
            .await
            .map_err(|e| format!("Invalid response: {}", e))?;

        if result.success {
            Ok(())
        } else {
            Err(result.error.unwrap_or_else(|| "Request failed".to_string()))
        }
    }

    // User operations
    pub async fn list_users(&self) -> Result<Vec<UserInfo>, String> {
        self.get("/api/users").await
    }

    pub async fn create_user(&self, username: &str, password: &str, role: Option<&str>) -> Result<UserInfo, String> {
        self.post(
            "/api/users",
            &CreateUserRequest {
                username: username.to_string(),
                password: password.to_string(),
                role: role.map(String::from),
                display_name: None,
            },
        )
        .await
    }

    pub async fn delete_user(&self, username: &str) -> Result<(), String> {
        self.delete(&format!("/api/users/{}", username)).await
    }

    pub async fn get_user(&self, username: &str) -> Result<UserInfo, String> {
        self.get(&format!("/api/users/{}", username)).await
    }

    // Group operations
    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>, String> {
        self.get("/api/groups").await
    }

    pub async fn create_group(&self, name: &str, email: &str) -> Result<GroupInfo, String> {
        self.post(
            "/api/groups",
            &CreateGroupRequest {
                name: name.to_string(),
                email: email.to_string(),
                description: None,
                members: vec![],
            },
        )
        .await
    }

    pub async fn delete_group(&self, name: &str) -> Result<(), String> {
        self.delete(&format!("/api/groups/{}", name)).await
    }

    pub async fn add_group_member(&self, group: &str, username: &str) -> Result<(), String> {
        self.post::<(), _>(
            &format!("/api/groups/{}/members", group),
            &GroupMemberRequest {
                username: username.to_string(),
            },
        )
        .await
    }

    pub async fn remove_group_member(&self, group: &str, username: &str) -> Result<(), String> {
        self.delete(&format!("/api/groups/{}/members/{}", group, username))
            .await
    }

    // Status
    pub async fn status(&self) -> Result<ServerStatus, String> {
        self.get("/api/status").await
    }

    // LDAP
    pub async fn ldap_test(&self) -> Result<String, String> {
        self.post("/api/ldap/test", &()).await
    }
}
