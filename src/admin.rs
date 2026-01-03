//! Admin CLI and management interface.
//!
//! Provides command-line tools for user and server management.

use crate::storage::Storage;
use crate::users::{AccountStatus, UserManager, UserQuota, UserRole};
use std::sync::Arc;

/// Admin command results
#[derive(Debug)]
pub enum AdminResult {
    Success(String),
    Error(String),
    UserList(Vec<UserListEntry>),
    UserInfo(UserInfoEntry),
    Stats(StatsEntry),
}

/// User list entry for display
#[derive(Debug)]
pub struct UserListEntry {
    pub username: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub quota_used: String,
    pub last_login: String,
}

/// Detailed user info
#[derive(Debug)]
pub struct UserInfoEntry {
    pub username: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub display_name: Option<String>,
    pub created_at: String,
    pub last_login: Option<String>,
    pub failed_attempts: u32,
    pub quota_used: u64,
    pub quota_max: u64,
    pub quota_percent: f32,
    pub message_count: u32,
    pub outgoing_today: u32,
    pub password_change_required: bool,
    pub allowed_ips: Vec<String>,
}

/// Server statistics
#[derive(Debug)]
pub struct StatsEntry {
    pub total_users: u32,
    pub active_users: u32,
    pub total_mailboxes: u32,
    pub total_emails: u64,
    pub total_storage_mb: f64,
}

/// Admin command handler
pub struct AdminHandler {
    storage: Arc<Storage>,
}

impl AdminHandler {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    /// Process an admin command
    pub async fn execute(&self, command: &str, args: &[&str], actor_username: &str) -> AdminResult {
        // Get the actor (admin performing the action)
        let actor = match self.storage.user_manager().get_user(actor_username).await {
            Some(u) => u,
            None => return AdminResult::Error("Actor user not found".to_string()),
        };

        // Check admin permissions
        if actor.role == UserRole::User {
            return AdminResult::Error("Permission denied: admin access required".to_string());
        }

        match command.to_lowercase().as_str() {
            "help" => self.cmd_help(),
            "list" | "ls" => self.cmd_list_users(args).await,
            "info" | "show" => self.cmd_user_info(args).await,
            "create" | "add" => self.cmd_create_user(args).await,
            "delete" | "rm" => self.cmd_delete_user(args, &actor).await,
            "passwd" | "password" => self.cmd_reset_password(args, &actor).await,
            "status" => self.cmd_set_status(args, &actor).await,
            "role" => self.cmd_set_role(args, &actor).await,
            "quota" => self.cmd_set_quota(args, &actor).await,
            "unlock" => self.cmd_unlock_user(args, &actor).await,
            "stats" => self.cmd_stats().await,
            "export" => self.cmd_export_users().await,
            _ => AdminResult::Error(format!("Unknown command: {}", command)),
        }
    }

    fn cmd_help(&self) -> AdminResult {
        AdminResult::Success(
            r#"
KISS Mail Admin Commands
========================

User Management:
  list [filter]         - List all users (filter: active, suspended, locked, admin)
  info <username>       - Show detailed user information
  create <user> <pass>  - Create a new user
  delete <username>     - Delete a user
  passwd <user> <pass>  - Reset user password
  status <user> <status> - Set status (active, suspended, disabled)
  role <user> <role>    - Set role (user, admin, superadmin)
  quota <user> <mb>     - Set mailbox quota in MB
  unlock <username>     - Unlock a locked account

Server:
  stats                 - Show server statistics
  export                - Export user list as JSON

Type 'help' for this message.
"#
            .to_string(),
        )
    }

    async fn cmd_list_users(&self, args: &[&str]) -> AdminResult {
        let filter = args.first().copied();

        let (role_filter, status_filter) = match filter {
            Some("active") => (None, Some(AccountStatus::Active)),
            Some("suspended") => (None, Some(AccountStatus::Suspended)),
            Some("locked") => (None, Some(AccountStatus::Locked)),
            Some("pending") => (None, Some(AccountStatus::PendingVerification)),
            Some("disabled") => (None, Some(AccountStatus::Disabled)),
            Some("admin") => (Some(UserRole::Admin), None),
            Some("superadmin") => (Some(UserRole::SuperAdmin), None),
            Some("user") => (Some(UserRole::User), None),
            _ => (None, None),
        };

        let users = self
            .storage
            .user_manager()
            .list_users_filtered(role_filter, status_filter, None)
            .await;

        let entries: Vec<UserListEntry> = users
            .iter()
            .map(|u| UserListEntry {
                username: u.username.clone(),
                email: u.email(),
                role: u.role.to_string(),
                status: u.status.to_string(),
                quota_used: format!(
                    "{:.1}% ({:.1} MB)",
                    u.quota.usage_percent(),
                    u.quota.current_usage as f64 / 1024.0 / 1024.0
                ),
                last_login: u
                    .last_login
                    .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "Never".to_string()),
            })
            .collect();

        AdminResult::UserList(entries)
    }

    async fn cmd_user_info(&self, args: &[&str]) -> AdminResult {
        let username = match args.first() {
            Some(u) => *u,
            None => return AdminResult::Error("Usage: info <username>".to_string()),
        };

        let user = match self.storage.user_manager().get_user(username).await {
            Some(u) => u,
            None => return AdminResult::Error(format!("User not found: {}", username)),
        };

        AdminResult::UserInfo(UserInfoEntry {
            username: user.username.clone(),
            email: user.email(),
            role: user.role.to_string(),
            status: user.status.to_string(),
            display_name: user.settings.display_name.clone(),
            created_at: user.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            last_login: user.last_login.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string()),
            failed_attempts: user.failed_login_attempts,
            quota_used: user.quota.current_usage,
            quota_max: user.quota.max_mailbox_size,
            quota_percent: user.quota.usage_percent(),
            message_count: user.quota.current_messages,
            outgoing_today: user.quota.outgoing_today,
            password_change_required: user.password_change_required,
            allowed_ips: user.allowed_ips.clone(),
        })
    }

    async fn cmd_create_user(&self, args: &[&str]) -> AdminResult {
        if args.len() < 2 {
            return AdminResult::Error("Usage: create <username> <password> [role]".to_string());
        }

        let username = args[0];
        let password = args[1];
        let role = args.get(2).map(|r| match r.to_lowercase().as_str() {
            "admin" => UserRole::Admin,
            "superadmin" => UserRole::SuperAdmin,
            _ => UserRole::User,
        });

        match self
            .storage
            .user_manager()
            .create_user(username, password, role)
            .await
        {
            Ok(user) => AdminResult::Success(format!(
                "Created user: {} ({})",
                user.username,
                user.email()
            )),
            Err(e) => AdminResult::Error(format!("Failed to create user: {}", e)),
        }
    }

    async fn cmd_delete_user(
        &self,
        args: &[&str],
        actor: &crate::users::UserAccount,
    ) -> AdminResult {
        let username = match args.first() {
            Some(u) => *u,
            None => return AdminResult::Error("Usage: delete <username>".to_string()),
        };

        match self
            .storage
            .user_manager()
            .delete_user(username, actor)
            .await
        {
            Ok(()) => AdminResult::Success(format!("Deleted user: {}", username)),
            Err(e) => AdminResult::Error(format!("Failed to delete user: {}", e)),
        }
    }

    async fn cmd_reset_password(
        &self,
        args: &[&str],
        actor: &crate::users::UserAccount,
    ) -> AdminResult {
        if args.len() < 2 {
            return AdminResult::Error("Usage: passwd <username> <new_password>".to_string());
        }

        let username = args[0];
        let new_password = args[1];
        let require_change = args.get(2).is_some_and(|a| *a == "--require-change");

        match self
            .storage
            .user_manager()
            .admin_reset_password(username, new_password, actor, require_change)
            .await
        {
            Ok(()) => AdminResult::Success(format!("Password reset for user: {}", username)),
            Err(e) => AdminResult::Error(format!("Failed to reset password: {}", e)),
        }
    }

    async fn cmd_set_status(
        &self,
        args: &[&str],
        actor: &crate::users::UserAccount,
    ) -> AdminResult {
        if args.len() < 2 {
            return AdminResult::Error(
                "Usage: status <username> <active|suspended|disabled>".to_string(),
            );
        }

        let username = args[0];
        let status = match args[1].to_lowercase().as_str() {
            "active" => AccountStatus::Active,
            "suspended" => AccountStatus::Suspended,
            "disabled" => AccountStatus::Disabled,
            "locked" => AccountStatus::Locked,
            "pending" => AccountStatus::PendingVerification,
            _ => {
                return AdminResult::Error(
                    "Invalid status. Use: active, suspended, disabled".to_string(),
                )
            }
        };

        match self
            .storage
            .user_manager()
            .set_status(username, status, actor)
            .await
        {
            Ok(()) => AdminResult::Success(format!("Status set to {} for user: {}", status, username)),
            Err(e) => AdminResult::Error(format!("Failed to set status: {}", e)),
        }
    }

    async fn cmd_set_role(
        &self,
        args: &[&str],
        actor: &crate::users::UserAccount,
    ) -> AdminResult {
        if args.len() < 2 {
            return AdminResult::Error("Usage: role <username> <user|admin|superadmin>".to_string());
        }

        let username = args[0];
        let role = match args[1].to_lowercase().as_str() {
            "user" => UserRole::User,
            "admin" => UserRole::Admin,
            "superadmin" => UserRole::SuperAdmin,
            _ => {
                return AdminResult::Error(
                    "Invalid role. Use: user, admin, superadmin".to_string(),
                )
            }
        };

        match self
            .storage
            .user_manager()
            .set_role(username, role, actor)
            .await
        {
            Ok(()) => AdminResult::Success(format!("Role set to {} for user: {}", role, username)),
            Err(e) => AdminResult::Error(format!("Failed to set role: {}", e)),
        }
    }

    async fn cmd_set_quota(
        &self,
        args: &[&str],
        actor: &crate::users::UserAccount,
    ) -> AdminResult {
        if args.len() < 2 {
            return AdminResult::Error("Usage: quota <username> <size_mb>".to_string());
        }

        let username = args[0];
        let size_mb: u64 = match args[1].parse() {
            Ok(s) => s,
            Err(_) => return AdminResult::Error("Invalid size. Must be a number in MB".to_string()),
        };

        let mut quota = UserQuota::default();
        quota.max_mailbox_size = size_mb * 1024 * 1024;

        match self
            .storage
            .user_manager()
            .set_quota(username, quota, actor)
            .await
        {
            Ok(()) => AdminResult::Success(format!(
                "Quota set to {} MB for user: {}",
                size_mb, username
            )),
            Err(e) => AdminResult::Error(format!("Failed to set quota: {}", e)),
        }
    }

    async fn cmd_unlock_user(
        &self,
        args: &[&str],
        actor: &crate::users::UserAccount,
    ) -> AdminResult {
        let username = match args.first() {
            Some(u) => *u,
            None => return AdminResult::Error("Usage: unlock <username>".to_string()),
        };

        match self
            .storage
            .user_manager()
            .set_status(username, AccountStatus::Active, actor)
            .await
        {
            Ok(()) => AdminResult::Success(format!("Unlocked user: {}", username)),
            Err(e) => AdminResult::Error(format!("Failed to unlock user: {}", e)),
        }
    }

    async fn cmd_stats(&self) -> AdminResult {
        let stats = self.storage.get_stats().await;

        AdminResult::Stats(StatsEntry {
            total_users: stats.user_stats.total_users,
            active_users: stats.user_stats.active_users,
            total_mailboxes: stats.total_mailboxes,
            total_emails: stats.total_emails,
            total_storage_mb: stats.total_size as f64 / 1024.0 / 1024.0,
        })
    }

    async fn cmd_export_users(&self) -> AdminResult {
        let users = self.storage.user_manager().list_users().await;
        
        let export: Vec<serde_json::Value> = users
            .iter()
            .map(|u| {
                serde_json::json!({
                    "username": u.username,
                    "email": u.email(),
                    "role": u.role.to_string(),
                    "status": u.status.to_string(),
                    "created_at": u.created_at.to_rfc3339(),
                    "last_login": u.last_login.map(|d| d.to_rfc3339()),
                    "quota_used_bytes": u.quota.current_usage,
                    "quota_max_bytes": u.quota.max_mailbox_size,
                    "message_count": u.quota.current_messages,
                })
            })
            .collect();

        match serde_json::to_string_pretty(&export) {
            Ok(json) => AdminResult::Success(json),
            Err(e) => AdminResult::Error(format!("Failed to export: {}", e)),
        }
    }
}

/// Format admin result for display
pub fn format_result(result: &AdminResult) -> String {
    match result {
        AdminResult::Success(msg) => msg.clone(),
        AdminResult::Error(msg) => format!("Error: {}", msg),
        AdminResult::UserList(entries) => {
            if entries.is_empty() {
                return "No users found.".to_string();
            }

            let mut output = String::new();
            output.push_str(&format!(
                "{:<20} {:<30} {:<12} {:<12} {:<20} {}\n",
                "USERNAME", "EMAIL", "ROLE", "STATUS", "QUOTA", "LAST LOGIN"
            ));
            output.push_str(&"-".repeat(110));
            output.push('\n');

            for entry in entries {
                output.push_str(&format!(
                    "{:<20} {:<30} {:<12} {:<12} {:<20} {}\n",
                    entry.username,
                    entry.email,
                    entry.role,
                    entry.status,
                    entry.quota_used,
                    entry.last_login
                ));
            }

            output.push_str(&format!("\nTotal: {} users", entries.len()));
            output
        }
        AdminResult::UserInfo(info) => {
            format!(
                r#"
User Information
================
Username:         {}
Email:            {}
Display Name:     {}
Role:             {}
Status:           {}
Created:          {}
Last Login:       {}
Failed Attempts:  {}

Quota:
  Used:           {:.2} MB / {:.2} MB ({:.1}%)
  Messages:       {}
  Outgoing Today: {}

Security:
  Password Change Required: {}
  Allowed IPs:              {}
"#,
                info.username,
                info.email,
                info.display_name.as_deref().unwrap_or("Not set"),
                info.role,
                info.status,
                info.created_at,
                info.last_login.as_deref().unwrap_or("Never"),
                info.failed_attempts,
                info.quota_used as f64 / 1024.0 / 1024.0,
                info.quota_max as f64 / 1024.0 / 1024.0,
                info.quota_percent,
                info.message_count,
                info.outgoing_today,
                if info.password_change_required { "Yes" } else { "No" },
                if info.allowed_ips.is_empty() {
                    "All".to_string()
                } else {
                    info.allowed_ips.join(", ")
                }
            )
        }
        AdminResult::Stats(stats) => {
            format!(
                r#"
Server Statistics
=================
Users:
  Total:          {}
  Active:         {}

Storage:
  Mailboxes:      {}
  Emails:         {}
  Total Size:     {:.2} MB
"#,
                stats.total_users,
                stats.active_users,
                stats.total_mailboxes,
                stats.total_emails,
                stats.total_storage_mb
            )
        }
    }
}

/// Parse command line for admin commands
pub fn parse_admin_command(input: &str) -> Option<(String, Vec<String>)> {
    let parts: Vec<&str> = input.trim().split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let command = parts[0].to_string();
    let args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();
    Some((command, args))
}
