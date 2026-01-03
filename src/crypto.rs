//! Zero-Knowledge Email Encryption (ProtonMail-style)
//!
//! This module provides automatic email encryption at rest:
//! - Each user has a unique X25519 key pair
//! - Private keys are encrypted with the user's password (via Argon2)
//! - Emails are encrypted using ChaCha20-Poly1305
//! - Emails between local users use end-to-end encryption
//! - External emails are encrypted at rest after reception
//!
//! # Security Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     User Registration                           │
//! │  Password → Argon2 → Key Encryption Key (KEK)                  │
//! │  Generate X25519 keypair                                        │
//! │  Private key encrypted with KEK → stored                        │
//! │  Public key → stored (unencrypted)                              │
//! └─────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Email Encryption                            │
//! │  1. Generate random symmetric key (per email)                   │
//! │  2. Encrypt email body with ChaCha20-Poly1305                   │
//! │  3. Encrypt symmetric key with recipient's public key           │
//! │  4. Store: encrypted_key + nonce + ciphertext                   │
//! └─────────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Email Decryption                            │
//! │  1. User logs in → password decrypts private key                │
//! │  2. Private key decrypts email's symmetric key                  │
//! │  3. Symmetric key decrypts email body                           │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

/// Size of symmetric encryption key (256 bits)
const KEY_SIZE: usize = 32;
/// Size of nonce for ChaCha20-Poly1305 (96 bits)
const NONCE_SIZE: usize = 12;
/// Size of Argon2 salt
const SALT_SIZE: usize = 16;

// ============================================================================
// Key Types
// ============================================================================

/// A user's encryption key pair
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserKeyPair {
    /// Public key (can be shared)
    pub public_key: Vec<u8>,
    /// Private key encrypted with user's password
    pub encrypted_private_key: Vec<u8>,
    /// Salt used for key derivation
    pub salt: Vec<u8>,
    /// Nonce used for private key encryption
    pub nonce: Vec<u8>,
    /// Key version for rotation
    pub version: u32,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Decrypted session keys (held in memory during user session)
#[derive(Clone)]
pub struct SessionKeys {
    /// Decrypted private key
    pub private_key: StaticSecret,
    /// Public key
    pub public_key: PublicKey,
    /// Username
    pub username: String,
}

/// An encrypted email
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedEmail {
    /// Encrypted symmetric key (encrypted with recipient's public key)
    pub encrypted_key: Vec<u8>,
    /// Nonce for key encryption
    pub key_nonce: Vec<u8>,
    /// Encrypted email body
    pub ciphertext: Vec<u8>,
    /// Nonce for body encryption
    pub body_nonce: Vec<u8>,
    /// Encryption version
    pub version: u8,
    /// Sender's public key (for verification)
    pub sender_public_key: Option<Vec<u8>>,
}

/// Encryption metadata stored with emails
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Whether the email is encrypted
    pub encrypted: bool,
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key version used for encryption
    pub key_version: u32,
    /// Whether this is end-to-end encrypted (sender is also local)
    pub e2e: bool,
}

impl Default for EncryptionMetadata {
    fn default() -> Self {
        Self {
            encrypted: false,
            algorithm: String::new(),
            key_version: 0,
            e2e: false,
        }
    }
}

// ============================================================================
// Crypto Manager
// ============================================================================

/// Manages encryption keys and operations
pub struct CryptoManager {
    /// User keys (username -> key pair)
    keys: Arc<RwLock<HashMap<String, UserKeyPair>>>,
    /// Active session keys (username -> decrypted keys)
    sessions: Arc<RwLock<HashMap<String, SessionKeys>>>,
    /// Data directory for key storage
    data_dir: PathBuf,
    /// Whether encryption is enabled
    enabled: bool,
}

impl CryptoManager {
    /// Create a new crypto manager
    pub fn new(data_dir: PathBuf) -> Self {
        let enabled = std::env::var("KISS_MAIL_ENCRYPTION")
            .map(|v| v != "false" && v != "0")
            .unwrap_or(true);

        let manager = Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            data_dir,
            enabled,
        };

        // Load keys synchronously during construction
        let keys_path = manager.data_dir.join("keys.json");
        if keys_path.exists() {
            if let Ok(data) = std::fs::read_to_string(&keys_path) {
                if let Ok(keys) = serde_json::from_str(&data) {
                    *manager.keys.blocking_write() = keys;
                }
            }
        }

        manager
    }

    /// Check if encryption is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Save keys to disk
    async fn save_keys(&self) -> Result<(), CryptoError> {
        let keys = self.keys.read().await;
        let data = serde_json::to_string_pretty(&*keys)
            .map_err(|e| CryptoError::StorageError(e.to_string()))?;
        
        let keys_path = self.data_dir.join("keys.json");
        tokio::fs::write(&keys_path, data)
            .await
            .map_err(|e| CryptoError::StorageError(e.to_string()))?;
        
        Ok(())
    }

    /// Generate a new key pair for a user
    pub async fn generate_keypair(
        &self,
        username: &str,
        password: &str,
    ) -> Result<UserKeyPair, CryptoError> {
        // Generate X25519 key pair
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);

        // Derive key encryption key from password
        let salt = generate_random_bytes(SALT_SIZE);
        let kek = derive_key_from_password(password, &salt)?;

        // Encrypt private key with KEK
        let nonce = generate_random_bytes(NONCE_SIZE);
        let cipher = ChaCha20Poly1305::new_from_slice(&kek)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        
        let encrypted_private_key = cipher
            .encrypt(Nonce::from_slice(&nonce), private_key.as_bytes().as_slice())
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let keypair = UserKeyPair {
            public_key: public_key.as_bytes().to_vec(),
            encrypted_private_key,
            salt,
            nonce,
            version: 1,
            created_at: chrono::Utc::now(),
        };

        // Store key pair
        {
            let mut keys = self.keys.write().await;
            keys.insert(username.to_string(), keypair.clone());
        }
        self.save_keys().await?;

        tracing::info!("Generated encryption keypair for user: {}", username);
        Ok(keypair)
    }

    /// Unlock a user's private key with their password
    pub async fn unlock_keys(
        &self,
        username: &str,
        password: &str,
    ) -> Result<SessionKeys, CryptoError> {
        let keys = self.keys.read().await;
        let keypair = keys
            .get(username)
            .ok_or_else(|| CryptoError::KeyNotFound(username.to_string()))?;

        // Derive KEK from password
        let kek = derive_key_from_password(password, &keypair.salt)?;

        // Decrypt private key
        let cipher = ChaCha20Poly1305::new_from_slice(&kek)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;
        
        let private_key_bytes = cipher
            .decrypt(
                Nonce::from_slice(&keypair.nonce),
                keypair.encrypted_private_key.as_slice(),
            )
            .map_err(|_| CryptoError::InvalidPassword)?;

        // Reconstruct keys
        let private_key_array: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| CryptoError::DecryptionError("Invalid key length".to_string()))?;
        
        let private_key = StaticSecret::from(private_key_array);
        let public_key = PublicKey::from(&private_key);

        let session = SessionKeys {
            private_key,
            public_key,
            username: username.to_string(),
        };

        // Store in active sessions
        {
            let mut sessions = self.sessions.write().await;
            sessions.insert(username.to_string(), session.clone());
        }

        Ok(session)
    }

    /// Lock (clear) a user's session keys
    pub async fn lock_keys(&self, username: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(username);
    }

    /// Get a user's public key
    pub async fn get_public_key(&self, username: &str) -> Option<Vec<u8>> {
        let keys = self.keys.read().await;
        keys.get(username).map(|k| k.public_key.clone())
    }

    /// Check if a user has encryption keys
    pub async fn has_keys(&self, username: &str) -> bool {
        let keys = self.keys.read().await;
        keys.contains_key(username)
    }

    /// Delete a user's keys
    pub async fn delete_keys(&self, username: &str) -> Result<(), CryptoError> {
        {
            let mut keys = self.keys.write().await;
            keys.remove(username);
        }
        {
            let mut sessions = self.sessions.write().await;
            sessions.remove(username);
        }
        self.save_keys().await?;
        Ok(())
    }

    /// Change a user's password (re-encrypt private key)
    pub async fn change_password(
        &self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), CryptoError> {
        // Unlock with old password
        let session = self.unlock_keys(username, old_password).await?;

        // Generate new salt and encrypt with new password
        let salt = generate_random_bytes(SALT_SIZE);
        let kek = derive_key_from_password(new_password, &salt)?;

        let nonce = generate_random_bytes(NONCE_SIZE);
        let cipher = ChaCha20Poly1305::new_from_slice(&kek)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        
        let encrypted_private_key = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                session.private_key.as_bytes().as_slice(),
            )
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        // Update stored keypair
        {
            let mut keys = self.keys.write().await;
            if let Some(keypair) = keys.get_mut(username) {
                keypair.encrypted_private_key = encrypted_private_key;
                keypair.salt = salt;
                keypair.nonce = nonce;
            }
        }
        self.save_keys().await?;

        tracing::info!("Re-encrypted keys for user after password change: {}", username);
        Ok(())
    }

    /// Encrypt an email for a recipient
    pub async fn encrypt_email(
        &self,
        recipient: &str,
        plaintext: &[u8],
        sender: Option<&str>,
    ) -> Result<EncryptedEmail, CryptoError> {
        if !self.enabled {
            return Err(CryptoError::Disabled);
        }

        // Get recipient's public key
        let recipient_public_key = self
            .get_public_key(recipient)
            .await
            .ok_or_else(|| CryptoError::KeyNotFound(recipient.to_string()))?;

        let recipient_pk_array: [u8; 32] = recipient_public_key
            .clone()
            .try_into()
            .map_err(|_| CryptoError::EncryptionError("Invalid public key".to_string()))?;
        let recipient_pk = PublicKey::from(recipient_pk_array);

        // Generate ephemeral key pair for key exchange
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform X25519 key exchange to derive shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pk);

        // Derive symmetric key from shared secret
        let symmetric_key = derive_symmetric_key(shared_secret.as_bytes());

        // Generate random nonce for body encryption
        let body_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt email body
        let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;
        
        let ciphertext = cipher
            .encrypt(&body_nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        // Get sender's public key if local
        let sender_public_key = if let Some(s) = sender {
            self.get_public_key(s).await
        } else {
            None
        };

        Ok(EncryptedEmail {
            encrypted_key: ephemeral_public.as_bytes().to_vec(),
            key_nonce: vec![], // Not used in X25519 scheme
            ciphertext,
            body_nonce: body_nonce.to_vec(),
            version: 1,
            sender_public_key,
        })
    }

    /// Decrypt an email
    pub async fn decrypt_email(
        &self,
        username: &str,
        encrypted: &EncryptedEmail,
    ) -> Result<Vec<u8>, CryptoError> {
        if !self.enabled {
            return Err(CryptoError::Disabled);
        }

        // Get session keys
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(username)
            .ok_or_else(|| CryptoError::SessionNotFound(username.to_string()))?;

        // Reconstruct ephemeral public key
        let ephemeral_pk_array: [u8; 32] = encrypted
            .encrypted_key
            .clone()
            .try_into()
            .map_err(|_| CryptoError::DecryptionError("Invalid ephemeral key".to_string()))?;
        let ephemeral_pk = PublicKey::from(ephemeral_pk_array);

        // Perform key exchange to recover shared secret
        let shared_secret = session.private_key.diffie_hellman(&ephemeral_pk);

        // Derive symmetric key
        let symmetric_key = derive_symmetric_key(shared_secret.as_bytes());

        // Decrypt email body
        let cipher = ChaCha20Poly1305::new_from_slice(&symmetric_key)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted.body_nonce);
        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|_| CryptoError::DecryptionError("Failed to decrypt email".to_string()))?;

        Ok(plaintext)
    }

    /// Encrypt an email for storage (simpler version for external emails)
    pub async fn encrypt_for_storage(
        &self,
        recipient: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, EncryptionMetadata), CryptoError> {
        if !self.enabled {
            return Ok((plaintext.to_vec(), EncryptionMetadata::default()));
        }

        if !self.has_keys(recipient).await {
            return Ok((plaintext.to_vec(), EncryptionMetadata::default()));
        }

        let encrypted = self.encrypt_email(recipient, plaintext, None).await?;
        let encrypted_data = serde_json::to_vec(&encrypted)
            .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

        let metadata = EncryptionMetadata {
            encrypted: true,
            algorithm: "X25519-ChaCha20-Poly1305".to_string(),
            key_version: 1,
            e2e: false,
        };

        Ok((encrypted_data, metadata))
    }

    /// Decrypt an email from storage
    pub async fn decrypt_from_storage(
        &self,
        username: &str,
        data: &[u8],
        metadata: &EncryptionMetadata,
    ) -> Result<Vec<u8>, CryptoError> {
        if !metadata.encrypted {
            return Ok(data.to_vec());
        }

        let encrypted: EncryptedEmail = serde_json::from_slice(data)
            .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

        self.decrypt_email(username, &encrypted).await
    }

    /// Get encryption status
    pub fn status(&self) -> CryptoStatus {
        CryptoStatus {
            enabled: self.enabled,
            algorithm: "X25519-ChaCha20-Poly1305".to_string(),
            key_derivation: "Argon2id".to_string(),
        }
    }

    /// Get stats
    pub async fn stats(&self) -> CryptoStats {
        let keys = self.keys.read().await;
        let sessions = self.sessions.read().await;
        
        CryptoStats {
            total_keys: keys.len(),
            active_sessions: sessions.len(),
            enabled: self.enabled,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Derive a key encryption key from password using Argon2id
fn derive_key_from_password(password: &str, salt: &[u8]) -> Result<[u8; KEY_SIZE], CryptoError> {
    // Use Argon2id with secure parameters
    let argon2 = Argon2::default();
    
    // Hash password to get key using the raw salt
    let mut output = [0u8; KEY_SIZE];
    
    // Use raw hash output with the salt directly
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output)
        .map_err(|e| CryptoError::KeyDerivationError(e.to_string()))?;

    Ok(output)
}

/// Derive a symmetric key from shared secret using SHA-256
fn derive_symmetric_key(shared_secret: &[u8]) -> [u8; KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(b"kiss-mail-v1");
    hasher.update(shared_secret);
    hasher.finalize().into()
}

/// Generate random bytes
fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Clone)]
pub enum CryptoError {
    /// Encryption is disabled
    Disabled,
    /// Key not found for user
    KeyNotFound(String),
    /// Invalid password
    InvalidPassword,
    /// Session not found (user not logged in)
    SessionNotFound(String),
    /// Key derivation error
    KeyDerivationError(String),
    /// Encryption error
    EncryptionError(String),
    /// Decryption error
    DecryptionError(String),
    /// Storage error
    StorageError(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "Encryption is disabled"),
            Self::KeyNotFound(u) => write!(f, "Encryption key not found for user: {}", u),
            Self::InvalidPassword => write!(f, "Invalid password"),
            Self::SessionNotFound(u) => write!(f, "Session not found for user: {} (not logged in)", u),
            Self::KeyDerivationError(e) => write!(f, "Key derivation error: {}", e),
            Self::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            Self::DecryptionError(e) => write!(f, "Decryption error: {}", e),
            Self::StorageError(e) => write!(f, "Storage error: {}", e),
        }
    }
}

impl std::error::Error for CryptoError {}

// ============================================================================
// Status Types
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct CryptoStatus {
    pub enabled: bool,
    pub algorithm: String,
    pub key_derivation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptoStats {
    pub total_keys: usize,
    pub active_sessions: usize,
    pub enabled: bool,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_keypair_generation() {
        let dir = tempdir().unwrap();
        let manager = CryptoManager::new(dir.path().to_path_buf());

        let keypair = manager.generate_keypair("alice", "password123").await.unwrap();
        
        assert_eq!(keypair.public_key.len(), 32);
        assert!(!keypair.encrypted_private_key.is_empty());
        assert_eq!(keypair.version, 1);
    }

    #[tokio::test]
    async fn test_unlock_keys() {
        let dir = tempdir().unwrap();
        let manager = CryptoManager::new(dir.path().to_path_buf());

        manager.generate_keypair("alice", "password123").await.unwrap();
        
        // Correct password should work
        let session = manager.unlock_keys("alice", "password123").await;
        assert!(session.is_ok());

        // Wrong password should fail
        let session = manager.unlock_keys("alice", "wrongpassword").await;
        assert!(matches!(session, Err(CryptoError::InvalidPassword)));
    }

    #[tokio::test]
    async fn test_encrypt_decrypt_email() {
        let dir = tempdir().unwrap();
        let manager = CryptoManager::new(dir.path().to_path_buf());

        // Setup recipient
        manager.generate_keypair("bob", "bobpass").await.unwrap();
        manager.unlock_keys("bob", "bobpass").await.unwrap();

        // Encrypt email
        let plaintext = b"Hello, Bob! This is a secret message.";
        let encrypted = manager.encrypt_email("bob", plaintext, None).await.unwrap();

        // Decrypt email
        let decrypted = manager.decrypt_email("bob", &encrypted).await.unwrap();
        
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_password_change() {
        let dir = tempdir().unwrap();
        let manager = CryptoManager::new(dir.path().to_path_buf());

        manager.generate_keypair("alice", "oldpass").await.unwrap();
        
        // Change password
        manager.change_password("alice", "oldpass", "newpass").await.unwrap();

        // Old password should fail
        let result = manager.unlock_keys("alice", "oldpass").await;
        assert!(matches!(result, Err(CryptoError::InvalidPassword)));

        // New password should work
        let result = manager.unlock_keys("alice", "newpass").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_storage_encryption() {
        let dir = tempdir().unwrap();
        let manager = CryptoManager::new(dir.path().to_path_buf());

        manager.generate_keypair("alice", "pass").await.unwrap();
        manager.unlock_keys("alice", "pass").await.unwrap();

        let plaintext = b"Encrypted at rest!";
        let (encrypted, metadata) = manager.encrypt_for_storage("alice", plaintext).await.unwrap();

        assert!(metadata.encrypted);
        assert_ne!(encrypted, plaintext);

        let decrypted = manager.decrypt_from_storage("alice", &encrypted, &metadata).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
