//! Group management module.
//!
//! Provides email distribution lists and user groups.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Group visibility/access level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupVisibility {
    /// Anyone can see and send to this group
    Public,
    /// Only members can see, anyone can send
    Internal,
    /// Only members can see and send
    Private,
    /// Hidden from directory, only owner/admins can manage
    Hidden,
}

impl Default for GroupVisibility {
    fn default() -> Self {
        Self::Internal
    }
}

/// Group type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupType {
    /// Distribution list - emails sent to group go to all members
    DistributionList,
    /// Security group - for access control (future use)
    SecurityGroup,
    /// Alias - single email forwarding to another address
    Alias,
}

impl Default for GroupType {
    fn default() -> Self {
        Self::DistributionList
    }
}

/// Group settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSettings {
    /// Allow external senders (non-members)
    pub allow_external: bool,
    /// Moderated - messages require approval
    pub moderated: bool,
    /// Reply-to behavior
    pub reply_to_group: bool,
    /// Subject prefix (e.g., "[dev-team]")
    pub subject_prefix: Option<String>,
    /// Footer added to messages
    pub footer: Option<String>,
    /// Max message size in bytes
    pub max_message_size: Option<usize>,
    /// Allowed sender domains (empty = all)
    pub allowed_domains: Vec<String>,
}

impl Default for GroupSettings {
    fn default() -> Self {
        Self {
            allow_external: false,
            moderated: false,
            reply_to_group: true,
            subject_prefix: None,
            footer: None,
            max_message_size: None,
            allowed_domains: Vec::new(),
        }
    }
}

/// A user group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Group name/identifier (e.g., "developers")
    pub name: String,
    /// Display name (e.g., "Development Team")
    pub display_name: String,
    /// Description
    pub description: String,
    /// Group email address (e.g., "developers@example.com")
    pub email: String,
    /// Group type
    pub group_type: GroupType,
    /// Visibility
    pub visibility: GroupVisibility,
    /// Owner username
    pub owner: String,
    /// Member usernames
    pub members: HashSet<String>,
    /// Manager usernames (can add/remove members)
    pub managers: HashSet<String>,
    /// Group settings
    pub settings: GroupSettings,
    /// Creation time
    pub created_at: DateTime<Utc>,
    /// Last modified time
    pub updated_at: DateTime<Utc>,
    /// Is group active
    pub active: bool,
}

impl Group {
    /// Create a new group
    pub fn new(name: String, email: String, owner: String) -> Self {
        let now = Utc::now();
        Self {
            display_name: name.clone(),
            name,
            description: String::new(),
            email,
            group_type: GroupType::default(),
            visibility: GroupVisibility::default(),
            owner: owner.clone(),
            members: HashSet::from([owner.clone()]),
            managers: HashSet::from([owner]),
            settings: GroupSettings::default(),
            created_at: now,
            updated_at: now,
            active: true,
        }
    }

    /// Check if user is a member
    pub fn is_member(&self, username: &str) -> bool {
        self.members.contains(username)
    }

    /// Check if user is a manager
    pub fn is_manager(&self, username: &str) -> bool {
        self.managers.contains(username) || self.owner == username
    }

    /// Check if user is the owner
    pub fn is_owner(&self, username: &str) -> bool {
        self.owner == username
    }

    /// Check if user can send to this group
    pub fn can_send(&self, username: &str, sender_domain: Option<&str>) -> bool {
        if !self.active {
            return false;
        }

        match self.visibility {
            GroupVisibility::Public => true,
            GroupVisibility::Internal | GroupVisibility::Hidden => {
                if self.settings.allow_external {
                    true
                } else {
                    self.is_member(username) || self.is_manager(username)
                }
            }
            GroupVisibility::Private => self.is_member(username),
        }
        .then(|| {
            // Check allowed domains if configured
            if !self.settings.allowed_domains.is_empty() {
                if let Some(domain) = sender_domain {
                    return self.settings.allowed_domains.iter().any(|d| d == domain);
                }
                return false;
            }
            true
        })
        .unwrap_or(false)
    }

    /// Add a member
    pub fn add_member(&mut self, username: String) -> bool {
        let added = self.members.insert(username);
        if added {
            self.updated_at = Utc::now();
        }
        added
    }

    /// Remove a member
    pub fn remove_member(&mut self, username: &str) -> bool {
        // Can't remove the owner
        if username == self.owner {
            return false;
        }
        let removed = self.members.remove(username);
        if removed {
            self.managers.remove(username);
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Add a manager
    pub fn add_manager(&mut self, username: String) -> bool {
        // Must be a member first
        if !self.is_member(&username) {
            return false;
        }
        let added = self.managers.insert(username);
        if added {
            self.updated_at = Utc::now();
        }
        added
    }

    /// Remove a manager
    pub fn remove_manager(&mut self, username: &str) -> bool {
        // Can't remove the owner as manager
        if username == self.owner {
            return false;
        }
        let removed = self.managers.remove(username);
        if removed {
            self.updated_at = Utc::now();
        }
        removed
    }

    /// Get all recipient emails for this group
    pub fn get_recipients(&self) -> Vec<String> {
        self.members.iter().cloned().collect()
    }
}

/// Group management errors
#[derive(Debug, Clone)]
pub enum GroupError {
    /// Group not found
    NotFound(String),
    /// Group already exists
    AlreadyExists(String),
    /// Not authorized
    NotAuthorized(String),
    /// Invalid group name
    InvalidName(String),
    /// User not found
    UserNotFound(String),
    /// Storage error
    StorageError(String),
}

impl std::fmt::Display for GroupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(name) => write!(f, "Group not found: {}", name),
            Self::AlreadyExists(name) => write!(f, "Group already exists: {}", name),
            Self::NotAuthorized(msg) => write!(f, "Not authorized: {}", msg),
            Self::InvalidName(msg) => write!(f, "Invalid group name: {}", msg),
            Self::UserNotFound(name) => write!(f, "User not found: {}", name),
            Self::StorageError(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for GroupError {}

/// Group manager
#[derive(Debug)]
pub struct GroupManager {
    /// Groups by name
    groups: Arc<RwLock<HashMap<String, Group>>>,
    /// Email to group name mapping
    email_map: Arc<RwLock<HashMap<String, String>>>,
    /// Data directory
    data_dir: PathBuf,
}

impl GroupManager {
    /// Create a new group manager
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            groups: Arc::new(RwLock::new(HashMap::new())),
            email_map: Arc::new(RwLock::new(HashMap::new())),
            data_dir,
        }
    }

    /// Load groups from disk
    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("groups.json");
        if !path.exists() {
            return Ok(());
        }

        let data = tokio::fs::read_to_string(&path).await?;
        let groups: HashMap<String, Group> = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Build email map
        let mut email_map = HashMap::new();
        for (name, group) in &groups {
            email_map.insert(group.email.to_lowercase(), name.clone());
        }

        *self.groups.write().await = groups;
        *self.email_map.write().await = email_map;

        tracing::info!("Loaded {} groups", self.groups.read().await.len());
        Ok(())
    }

    /// Save groups to disk
    pub async fn save(&self) -> Result<(), std::io::Error> {
        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("groups.json");

        let groups = self.groups.read().await;
        let data = serde_json::to_string_pretty(&*groups)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        tokio::fs::write(&path, data).await
    }

    /// Create a new group
    pub async fn create(
        &self,
        name: &str,
        email: &str,
        owner: &str,
    ) -> Result<Group, GroupError> {
        // Validate name
        if name.is_empty() || name.len() > 64 {
            return Err(GroupError::InvalidName(
                "Name must be 1-64 characters".to_string(),
            ));
        }
        if !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(GroupError::InvalidName(
                "Name can only contain alphanumeric, dash, underscore".to_string(),
            ));
        }

        let name_lower = name.to_lowercase();
        let email_lower = email.to_lowercase();

        let mut groups = self.groups.write().await;

        // Check if exists
        if groups.contains_key(&name_lower) {
            return Err(GroupError::AlreadyExists(name.to_string()));
        }

        // Check if email is taken
        let email_map = self.email_map.read().await;
        if email_map.contains_key(&email_lower) {
            return Err(GroupError::AlreadyExists(format!("Email {} already in use", email)));
        }
        drop(email_map);

        // Create group
        let group = Group::new(name_lower.clone(), email_lower.clone(), owner.to_string());
        groups.insert(name_lower.clone(), group.clone());

        // Update email map
        self.email_map
            .write()
            .await
            .insert(email_lower, name_lower);

        drop(groups);
        let _ = self.save().await;

        tracing::info!("Created group '{}' owned by '{}'", name, owner);
        Ok(group)
    }

    /// Delete a group
    pub async fn delete(&self, name: &str, actor: &str) -> Result<(), GroupError> {
        let name_lower = name.to_lowercase();
        let mut groups = self.groups.write().await;

        let group = groups
            .get(&name_lower)
            .ok_or_else(|| GroupError::NotFound(name.to_string()))?;

        // Only owner can delete (or admin via elevated privileges)
        if group.owner != actor {
            return Err(GroupError::NotAuthorized(
                "Only the owner can delete a group".to_string(),
            ));
        }

        let email = group.email.clone();
        groups.remove(&name_lower);

        // Update email map
        self.email_map.write().await.remove(&email);

        drop(groups);
        let _ = self.save().await;

        tracing::info!("Deleted group '{}' by '{}'", name, actor);
        Ok(())
    }

    /// Get a group by name
    pub async fn get(&self, name: &str) -> Option<Group> {
        self.groups.read().await.get(&name.to_lowercase()).cloned()
    }

    /// Get a group by email address
    pub async fn get_by_email(&self, email: &str) -> Option<Group> {
        let email_lower = email.to_lowercase();
        let email_map = self.email_map.read().await;
        
        if let Some(name) = email_map.get(&email_lower) {
            return self.groups.read().await.get(name).cloned();
        }
        None
    }

    /// Check if an email address is a group
    pub async fn is_group_email(&self, email: &str) -> bool {
        self.email_map
            .read()
            .await
            .contains_key(&email.to_lowercase())
    }

    /// Expand a group email to member emails
    pub async fn expand_recipients(&self, email: &str) -> Option<Vec<String>> {
        self.get_by_email(email)
            .await
            .filter(|g| g.active)
            .map(|g| g.get_recipients())
    }

    /// Add member to group
    pub async fn add_member(
        &self,
        group_name: &str,
        username: &str,
        actor: &str,
    ) -> Result<(), GroupError> {
        let name_lower = group_name.to_lowercase();
        let mut groups = self.groups.write().await;

        let group = groups
            .get_mut(&name_lower)
            .ok_or_else(|| GroupError::NotFound(group_name.to_string()))?;

        // Check authorization
        if !group.is_manager(actor) {
            return Err(GroupError::NotAuthorized(
                "Only managers can add members".to_string(),
            ));
        }

        group.add_member(username.to_string());

        drop(groups);
        let _ = self.save().await;

        tracing::info!(
            "Added '{}' to group '{}' by '{}'",
            username,
            group_name,
            actor
        );
        Ok(())
    }

    /// Remove member from group
    pub async fn remove_member(
        &self,
        group_name: &str,
        username: &str,
        actor: &str,
    ) -> Result<(), GroupError> {
        let name_lower = group_name.to_lowercase();
        let mut groups = self.groups.write().await;

        let group = groups
            .get_mut(&name_lower)
            .ok_or_else(|| GroupError::NotFound(group_name.to_string()))?;

        // Check authorization
        if !group.is_manager(actor) {
            return Err(GroupError::NotAuthorized(
                "Only managers can remove members".to_string(),
            ));
        }

        if !group.remove_member(username) {
            return Err(GroupError::NotAuthorized(
                "Cannot remove the group owner".to_string(),
            ));
        }

        drop(groups);
        let _ = self.save().await;

        tracing::info!(
            "Removed '{}' from group '{}' by '{}'",
            username,
            group_name,
            actor
        );
        Ok(())
    }

    /// List all groups (filtered by visibility for non-admins)
    pub async fn list(&self, viewer: Option<&str>, is_admin: bool) -> Vec<Group> {
        self.groups
            .read()
            .await
            .values()
            .filter(|g| {
                if is_admin {
                    return true;
                }
                match g.visibility {
                    GroupVisibility::Public | GroupVisibility::Internal => true,
                    GroupVisibility::Private => {
                        viewer.map(|v| g.is_member(v)).unwrap_or(false)
                    }
                    GroupVisibility::Hidden => {
                        viewer.map(|v| g.is_manager(v)).unwrap_or(false)
                    }
                }
            })
            .cloned()
            .collect()
    }

    /// List groups for a user
    pub async fn list_user_groups(&self, username: &str) -> Vec<Group> {
        self.groups
            .read()
            .await
            .values()
            .filter(|g| g.is_member(username))
            .cloned()
            .collect()
    }

    /// Update group settings
    pub async fn update_settings(
        &self,
        group_name: &str,
        settings: GroupSettings,
        actor: &str,
    ) -> Result<(), GroupError> {
        let name_lower = group_name.to_lowercase();
        let mut groups = self.groups.write().await;

        let group = groups
            .get_mut(&name_lower)
            .ok_or_else(|| GroupError::NotFound(group_name.to_string()))?;

        // Only owner can change settings
        if !group.is_owner(actor) {
            return Err(GroupError::NotAuthorized(
                "Only the owner can change settings".to_string(),
            ));
        }

        group.settings = settings;
        group.updated_at = Utc::now();

        drop(groups);
        let _ = self.save().await;

        Ok(())
    }

    /// Update group visibility
    pub async fn set_visibility(
        &self,
        group_name: &str,
        visibility: GroupVisibility,
        actor: &str,
    ) -> Result<(), GroupError> {
        let name_lower = group_name.to_lowercase();
        let mut groups = self.groups.write().await;

        let group = groups
            .get_mut(&name_lower)
            .ok_or_else(|| GroupError::NotFound(group_name.to_string()))?;

        if !group.is_owner(actor) {
            return Err(GroupError::NotAuthorized(
                "Only the owner can change visibility".to_string(),
            ));
        }

        group.visibility = visibility;
        group.updated_at = Utc::now();

        drop(groups);
        let _ = self.save().await;

        Ok(())
    }

    /// Set group description
    pub async fn set_description(
        &self,
        group_name: &str,
        description: String,
        actor: &str,
    ) -> Result<(), GroupError> {
        let name_lower = group_name.to_lowercase();
        let mut groups = self.groups.write().await;

        let group = groups
            .get_mut(&name_lower)
            .ok_or_else(|| GroupError::NotFound(group_name.to_string()))?;

        if !group.is_manager(actor) {
            return Err(GroupError::NotAuthorized(
                "Only managers can change description".to_string(),
            ));
        }

        group.description = description;
        group.updated_at = Utc::now();

        drop(groups);
        let _ = self.save().await;

        Ok(())
    }

    /// Add a manager to a group
    pub async fn add_manager(
        &self,
        group_name: &str,
        username: &str,
        actor: &str,
    ) -> Result<(), GroupError> {
        let name_lower = group_name.to_lowercase();
        let mut groups = self.groups.write().await;

        let group = groups
            .get_mut(&name_lower)
            .ok_or_else(|| GroupError::NotFound(group_name.to_string()))?;

        if !group.is_owner(actor) {
            return Err(GroupError::NotAuthorized(
                "Only the owner can add managers".to_string(),
            ));
        }

        if !group.add_manager(username.to_string()) {
            return Err(GroupError::UserNotFound(format!(
                "{} is not a member of the group",
                username
            )));
        }

        drop(groups);
        let _ = self.save().await;

        Ok(())
    }

    /// Get group stats
    pub async fn get_stats(&self) -> GroupStats {
        let groups = self.groups.read().await;
        let total = groups.len();
        let active = groups.values().filter(|g| g.active).count();
        let total_members: usize = groups.values().map(|g| g.members.len()).sum();

        GroupStats {
            total_groups: total,
            active_groups: active,
            total_memberships: total_members,
        }
    }
}

/// Group statistics
#[derive(Debug, Clone)]
pub struct GroupStats {
    pub total_groups: usize,
    pub active_groups: usize,
    pub total_memberships: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_group_creation() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());

        let group = manager
            .create("developers", "dev@example.com", "alice")
            .await
            .unwrap();

        assert_eq!(group.name, "developers");
        assert_eq!(group.owner, "alice");
        assert!(group.is_member("alice"));
        assert!(group.is_manager("alice"));
    }

    #[tokio::test]
    async fn test_member_management() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());

        manager
            .create("team", "team@example.com", "alice")
            .await
            .unwrap();

        // Add member
        manager.add_member("team", "bob", "alice").await.unwrap();

        let group = manager.get("team").await.unwrap();
        assert!(group.is_member("bob"));
        assert!(!group.is_manager("bob"));

        // Remove member
        manager.remove_member("team", "bob", "alice").await.unwrap();

        let group = manager.get("team").await.unwrap();
        assert!(!group.is_member("bob"));
    }

    #[tokio::test]
    async fn test_email_expansion() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());

        manager
            .create("all", "all@example.com", "admin")
            .await
            .unwrap();
        manager.add_member("all", "bob", "admin").await.unwrap();
        manager.add_member("all", "carol", "admin").await.unwrap();

        let recipients = manager.expand_recipients("all@example.com").await.unwrap();
        assert_eq!(recipients.len(), 3);
        assert!(recipients.contains(&"admin".to_string()));
        assert!(recipients.contains(&"bob".to_string()));
        assert!(recipients.contains(&"carol".to_string()));
    }

    #[tokio::test]
    async fn test_authorization() {
        let dir = tempdir().unwrap();
        let manager = GroupManager::new(dir.path().to_path_buf());

        manager
            .create("private", "private@example.com", "alice")
            .await
            .unwrap();

        // Non-manager can't add members
        let result = manager.add_member("private", "carol", "bob").await;
        assert!(matches!(result, Err(GroupError::NotAuthorized(_))));

        // Can't remove owner
        let result = manager.remove_member("private", "alice", "alice").await;
        assert!(matches!(result, Err(GroupError::NotAuthorized(_))));
    }

    #[tokio::test]
    async fn test_persistence() {
        let dir = tempdir().unwrap();

        // Create and save
        {
            let manager = GroupManager::new(dir.path().to_path_buf());
            manager
                .create("test", "test@example.com", "user")
                .await
                .unwrap();
            manager.add_member("test", "member1", "user").await.unwrap();
        }

        // Load and verify
        {
            let manager = GroupManager::new(dir.path().to_path_buf());
            manager.load().await.unwrap();

            let group = manager.get("test").await.unwrap();
            assert_eq!(group.members.len(), 2);
            assert!(group.is_member("member1"));
        }
    }
}
