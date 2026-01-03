//! AI-driven spam detection using Naive Bayes classification.
//!
//! This module implements a self-learning Bayesian spam filter that:
//! - Learns from emails marked as spam/ham
//! - Uses TF-IDF-style tokenization
//! - Calculates spam probability using Bayes' theorem
//! - Persists learned data to disk

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Spam classification result
#[derive(Debug, Clone)]
pub struct SpamClassification {
    /// Probability that the email is spam (0.0 - 1.0)
    pub spam_probability: f64,
    /// Whether classified as spam (probability > threshold)
    pub is_spam: bool,
    /// Top words contributing to spam score
    pub spam_indicators: Vec<(String, f64)>,
    /// Top words contributing to ham score  
    pub ham_indicators: Vec<(String, f64)>,
    /// Confidence level (how certain the classifier is)
    pub confidence: f64,
}

/// Token statistics for Bayesian learning
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenStats {
    /// Times this token appeared in spam
    spam_count: u64,
    /// Times this token appeared in ham (non-spam)
    ham_count: u64,
}

/// Bayesian spam classifier with persistent learning
#[derive(Debug)]
pub struct SpamClassifier {
    /// Token frequency data
    tokens: Arc<RwLock<HashMap<String, TokenStats>>>,
    /// Total spam emails seen
    total_spam: Arc<RwLock<u64>>,
    /// Total ham emails seen
    total_ham: Arc<RwLock<u64>>,
    /// Spam classification threshold (default: 0.7)
    pub threshold: f64,
    /// Minimum token occurrences to be considered (default: 3)
    pub min_occurrences: u64,
    /// Data directory for persistence
    data_dir: PathBuf,
    /// Whether the model has been modified since last save
    dirty: Arc<RwLock<bool>>,
}

impl SpamClassifier {
    /// Create a new spam classifier
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            total_spam: Arc::new(RwLock::new(0)),
            total_ham: Arc::new(RwLock::new(0)),
            threshold: 0.7,
            min_occurrences: 3,
            data_dir,
            dirty: Arc::new(RwLock::new(false)),
        }
    }

    /// Load learned data from disk
    pub async fn load(&self) -> Result<(), std::io::Error> {
        let path = self.data_dir.join("spam_classifier.json");
        if !path.exists() {
            // Initialize with seed data
            self.seed_initial_data().await;
            return Ok(());
        }

        let data = tokio::fs::read_to_string(&path).await?;
        let saved: SavedClassifier = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        *self.tokens.write().await = saved.tokens;
        *self.total_spam.write().await = saved.total_spam;
        *self.total_ham.write().await = saved.total_ham;

        tracing::info!(
            "Loaded spam classifier: {} tokens, {} spam, {} ham",
            self.tokens.read().await.len(),
            saved.total_spam,
            saved.total_ham
        );

        Ok(())
    }

    /// Save learned data to disk
    pub async fn save(&self) -> Result<(), std::io::Error> {
        if !*self.dirty.read().await {
            return Ok(());
        }

        tokio::fs::create_dir_all(&self.data_dir).await?;
        let path = self.data_dir.join("spam_classifier.json");

        let saved = SavedClassifier {
            tokens: self.tokens.read().await.clone(),
            total_spam: *self.total_spam.read().await,
            total_ham: *self.total_ham.read().await,
        };

        let data = serde_json::to_string(&saved)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        tokio::fs::write(&path, data).await?;
        *self.dirty.write().await = false;

        Ok(())
    }

    /// Classify an email as spam or ham
    pub async fn classify(&self, email: &str) -> SpamClassification {
        let tokens = self.tokenize(email);
        let total_spam = *self.total_spam.read().await;
        let total_ham = *self.total_ham.read().await;

        // Not enough training data
        if total_spam < 10 || total_ham < 10 {
            return SpamClassification {
                spam_probability: 0.5,
                is_spam: false,
                spam_indicators: vec![],
                ham_indicators: vec![],
                confidence: 0.0,
            };
        }

        let token_data = self.tokens.read().await;
        let mut log_spam_prob = 0.0f64;
        let mut log_ham_prob = 0.0f64;
        let mut spam_indicators = Vec::new();
        let mut ham_indicators = Vec::new();

        // Prior probabilities (with Laplace smoothing)
        let prior_spam = (total_spam as f64 + 1.0) / (total_spam + total_ham + 2) as f64;
        let prior_ham = (total_ham as f64 + 1.0) / (total_spam + total_ham + 2) as f64;

        log_spam_prob += prior_spam.ln();
        log_ham_prob += prior_ham.ln();

        for token in &tokens {
            if let Some(stats) = token_data.get(token) {
                // Skip rare tokens
                if stats.spam_count + stats.ham_count < self.min_occurrences {
                    continue;
                }

                // Probability of token given spam (with Laplace smoothing)
                let p_token_spam = (stats.spam_count as f64 + 1.0) / (total_spam as f64 + 2.0);
                let p_token_ham = (stats.ham_count as f64 + 1.0) / (total_ham as f64 + 2.0);

                log_spam_prob += p_token_spam.ln();
                log_ham_prob += p_token_ham.ln();

                // Track indicators
                let spam_ratio = p_token_spam / (p_token_spam + p_token_ham);
                if spam_ratio > 0.7 {
                    spam_indicators.push((token.clone(), spam_ratio));
                } else if spam_ratio < 0.3 {
                    ham_indicators.push((token.clone(), 1.0 - spam_ratio));
                }
            }
        }

        // Convert log probabilities to probability using log-sum-exp trick
        let max_log = log_spam_prob.max(log_ham_prob);
        let spam_exp = (log_spam_prob - max_log).exp();
        let ham_exp = (log_ham_prob - max_log).exp();
        let spam_probability = spam_exp / (spam_exp + ham_exp);

        // Calculate confidence based on how far from 0.5 we are
        let confidence = (spam_probability - 0.5).abs() * 2.0;

        // Sort indicators by strength
        spam_indicators.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ham_indicators.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Keep top 10 indicators
        spam_indicators.truncate(10);
        ham_indicators.truncate(10);

        SpamClassification {
            spam_probability,
            is_spam: spam_probability >= self.threshold,
            spam_indicators,
            ham_indicators,
            confidence,
        }
    }

    /// Train the classifier with a spam email
    pub async fn learn_spam(&self, email: &str) {
        let tokens = self.tokenize(email);
        let mut token_data = self.tokens.write().await;

        for token in tokens {
            let stats = token_data.entry(token).or_default();
            stats.spam_count += 1;
        }

        *self.total_spam.write().await += 1;
        *self.dirty.write().await = true;
    }

    /// Train the classifier with a ham (non-spam) email
    pub async fn learn_ham(&self, email: &str) {
        let tokens = self.tokenize(email);
        let mut token_data = self.tokens.write().await;

        for token in tokens {
            let stats = token_data.entry(token).or_default();
            stats.ham_count += 1;
        }

        *self.total_ham.write().await += 1;
        *self.dirty.write().await = true;
    }

    /// Tokenize email into words/features
    fn tokenize(&self, email: &str) -> Vec<String> {
        let email_lower = email.to_lowercase();
        let mut tokens = Vec::new();
        let mut seen = std::collections::HashSet::new();

        // Extract words (3-20 chars, alphanumeric)
        for word in email_lower.split(|c: char| !c.is_alphanumeric() && c != '\'') {
            let word = word.trim_matches('\'');
            if word.len() >= 3 && word.len() <= 20 && !seen.contains(word) {
                // Skip pure numbers
                if !word.chars().all(|c| c.is_numeric()) {
                    tokens.push(word.to_string());
                    seen.insert(word.to_string());
                }
            }
        }

        // Extract special features
        self.extract_features(&email_lower, &mut tokens, &mut seen);

        tokens
    }

    /// Extract special features from email
    fn extract_features(
        &self,
        email: &str,
        tokens: &mut Vec<String>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        // URL features
        let url_count = email.matches("http://").count() + email.matches("https://").count();
        if url_count > 0 {
            tokens.push(format!("__URL_COUNT_{}", url_count.min(10)));
        }
        
        // Suspicious URL patterns
        if email.contains("bit.ly") || email.contains("tinyurl") || email.contains("t.co") {
            if seen.insert("__SHORT_URL".to_string()) {
                tokens.push("__SHORT_URL".to_string());
            }
        }

        // CAPS features
        let caps_ratio = email.chars().filter(|c| c.is_uppercase()).count() as f64
            / email.chars().filter(|c| c.is_alphabetic()).count().max(1) as f64;
        if caps_ratio > 0.3 {
            tokens.push("__HIGH_CAPS".to_string());
        }

        // Exclamation marks
        let exclaim_count = email.matches('!').count();
        if exclaim_count > 3 {
            tokens.push(format!("__EXCLAIM_{}", exclaim_count.min(10)));
        }

        // Dollar signs (money)
        if email.contains('$') {
            tokens.push("__HAS_DOLLAR".to_string());
        }

        // Urgency words
        let urgency_words = ["urgent", "immediately", "act now", "limited time", "expires", "deadline"];
        for word in &urgency_words {
            if email.contains(word) && seen.insert(format!("__URGENT_{}", word)) {
                tokens.push(format!("__URGENT_{}", word));
            }
        }

        // Phishing patterns
        let phishing_words = ["verify", "confirm", "suspend", "account", "password", "login", "click here"];
        let mut phishing_count = 0;
        for word in &phishing_words {
            if email.contains(word) {
                phishing_count += 1;
            }
        }
        if phishing_count >= 3 {
            tokens.push("__PHISHING_PATTERN".to_string());
        }

        // HTML features
        if email.contains("<html") || email.contains("<body") {
            tokens.push("__HAS_HTML".to_string());
        }
        if email.contains("style=") || email.contains("<style") {
            tokens.push("__HAS_STYLE".to_string());
        }

        // Image-heavy (common in spam)
        let img_count = email.matches("<img").count();
        if img_count > 2 {
            tokens.push(format!("__IMG_COUNT_{}", img_count.min(10)));
        }

        // Base64 content (attachments)
        if email.contains("base64") {
            tokens.push("__HAS_BASE64".to_string());
        }

        // Missing headers (suspicious)
        if !email.to_lowercase().contains("message-id:") {
            tokens.push("__NO_MESSAGE_ID".to_string());
        }
        if !email.to_lowercase().contains("date:") {
            tokens.push("__NO_DATE".to_string());
        }

        // Sender patterns
        if email.contains("@") {
            // Extract domain from From header
            if let Some(from_start) = email.find("from:") {
                let from_section = &email[from_start..];
                if let Some(at_pos) = from_section.find('@') {
                    let domain_start = at_pos + 1;
                    let domain_end = from_section[domain_start..]
                        .find(|c: char| !c.is_alphanumeric() && c != '.' && c != '-')
                        .map(|p| domain_start + p)
                        .unwrap_or(from_section.len().min(domain_start + 50));
                    let domain = &from_section[domain_start..domain_end];
                    
                    // Suspicious TLDs
                    let suspicious_tlds = [".xyz", ".top", ".work", ".click", ".loan", ".racing", ".win"];
                    for tld in &suspicious_tlds {
                        if domain.ends_with(tld) {
                            tokens.push(format!("__SUSPICIOUS_TLD_{}", tld));
                            break;
                        }
                    }
                }
            }
        }

        // Bigrams for common spam phrases
        let spam_bigrams = [
            ("free", "money"),
            ("click", "here"),
            ("act", "now"),
            ("limited", "time"),
            ("you", "won"),
            ("dear", "friend"),
            ("bank", "account"),
            ("credit", "card"),
            ("nigerian", "prince"),
            ("wire", "transfer"),
        ];
        
        for (w1, w2) in &spam_bigrams {
            if email.contains(w1) && email.contains(w2) {
                if seen.insert(format!("__BIGRAM_{}_{}", w1, w2)) {
                    tokens.push(format!("__BIGRAM_{}_{}", w1, w2));
                }
            }
        }
    }

    /// Seed initial training data with common spam/ham patterns
    async fn seed_initial_data(&self) {
        tracing::info!("Seeding spam classifier with initial training data");

        // Common spam words and patterns
        let spam_seeds = [
            "viagra", "cialis", "lottery", "winner", "congratulations", "million",
            "dollars", "inheritance", "beneficiary", "nigeria", "prince", "urgent",
            "wire", "transfer", "casino", "gambling", "pills", "pharmacy", "discount",
            "cheap", "free", "click", "subscribe", "unsubscribe", "opt-out",
            "limited", "offer", "expires", "act", "now", "immediately",
            "guarantee", "credit", "debt", "loan", "mortgage", "refinance",
            "weight", "loss", "diet", "enhancement", "enlargement",
            "__SHORT_URL", "__HIGH_CAPS", "__PHISHING_PATTERN", "__NO_MESSAGE_ID",
            "__SUSPICIOUS_TLD_.xyz", "__SUSPICIOUS_TLD_.top", "__BIGRAM_free_money",
            "__BIGRAM_click_here", "__BIGRAM_act_now", "__BIGRAM_dear_friend",
        ];

        // Common ham words
        let ham_seeds = [
            "meeting", "schedule", "project", "report", "document", "attached",
            "please", "thanks", "thank", "regards", "sincerely", "best",
            "review", "feedback", "update", "status", "discussion", "team",
            "monday", "tuesday", "wednesday", "thursday", "friday", "week",
            "invoice", "receipt", "order", "shipping", "delivery", "tracking",
            "conference", "call", "agenda", "minutes", "presentation",
            "github", "commit", "merge", "pull", "request", "issue", "bug",
            "deployment", "release", "version", "update", "patch",
        ];

        let mut tokens = self.tokens.write().await;

        // Seed spam tokens
        for word in &spam_seeds {
            let stats = tokens.entry(word.to_string()).or_default();
            stats.spam_count += 50;
            stats.ham_count += 5;
        }

        // Seed ham tokens
        for word in &ham_seeds {
            let stats = tokens.entry(word.to_string()).or_default();
            stats.spam_count += 5;
            stats.ham_count += 50;
        }

        *self.total_spam.write().await = 100;
        *self.total_ham.write().await = 100;
        *self.dirty.write().await = true;

        drop(tokens);
        let _ = self.save().await;

        tracing::info!("Spam classifier seeded with initial data");
    }

    /// Get classifier statistics
    pub async fn stats(&self) -> ClassifierStats {
        let tokens = self.tokens.read().await;
        let total_spam = *self.total_spam.read().await;
        let total_ham = *self.total_ham.read().await;

        // Find most spammy and hammy words
        let mut spam_words: Vec<_> = tokens
            .iter()
            .filter(|(_, s)| s.spam_count + s.ham_count >= self.min_occurrences)
            .map(|(word, stats)| {
                let ratio = stats.spam_count as f64 / (stats.spam_count + stats.ham_count) as f64;
                (word.clone(), ratio, stats.spam_count + stats.ham_count)
            })
            .collect();

        spam_words.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let top_spam_words: Vec<_> = spam_words.iter().take(20).map(|(w, r, _)| (w.clone(), *r)).collect();

        spam_words.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        let top_ham_words: Vec<_> = spam_words.iter().take(20).map(|(w, r, _)| (w.clone(), 1.0 - *r)).collect();

        ClassifierStats {
            total_tokens: tokens.len(),
            total_spam_emails: total_spam,
            total_ham_emails: total_ham,
            top_spam_words,
            top_ham_words,
            threshold: self.threshold,
        }
    }

    /// Set the spam threshold
    pub fn set_threshold(&mut self, threshold: f64) {
        self.threshold = threshold.clamp(0.0, 1.0);
    }
}

/// Saved classifier data for persistence
#[derive(Serialize, Deserialize)]
struct SavedClassifier {
    tokens: HashMap<String, TokenStats>,
    total_spam: u64,
    total_ham: u64,
}

/// Classifier statistics
#[derive(Debug, Clone)]
pub struct ClassifierStats {
    pub total_tokens: usize,
    pub total_spam_emails: u64,
    pub total_ham_emails: u64,
    pub top_spam_words: Vec<(String, f64)>,
    pub top_ham_words: Vec<(String, f64)>,
    pub threshold: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_classifier_basics() {
        let dir = tempdir().unwrap();
        let classifier = SpamClassifier::new(dir.path().to_path_buf());
        classifier.load().await.unwrap();

        // Train with some spam
        for _ in 0..20 {
            classifier.learn_spam("Buy cheap viagra now! Click here for free money! Act immediately!").await;
            classifier.learn_spam("Congratulations! You won the lottery! Wire transfer required.").await;
        }

        // Train with some ham
        for _ in 0..20 {
            classifier.learn_ham("Hi, please review the attached document for our meeting tomorrow.").await;
            classifier.learn_ham("The project status update is ready. Let me know your feedback.").await;
        }

        // Test classification
        let spam_result = classifier.classify("FREE MONEY! Click here NOW to claim your prize!!!").await;
        assert!(spam_result.spam_probability > 0.5, "Should classify as likely spam");

        let ham_result = classifier.classify("Please review the attached report and send your feedback.").await;
        assert!(ham_result.spam_probability < 0.5, "Should classify as likely ham");
    }

    #[tokio::test]
    async fn test_persistence() {
        let dir = tempdir().unwrap();
        
        // Create and train
        {
            let classifier = SpamClassifier::new(dir.path().to_path_buf());
            classifier.load().await.unwrap();
            
            for _ in 0..10 {
                classifier.learn_spam("spam test message").await;
                classifier.learn_ham("ham test message").await;
            }
            
            classifier.save().await.unwrap();
        }

        // Load and verify
        {
            let classifier = SpamClassifier::new(dir.path().to_path_buf());
            classifier.load().await.unwrap();
            
            let stats = classifier.stats().await;
            assert!(stats.total_spam_emails > 100); // Seeded + trained
            assert!(stats.total_ham_emails > 100);
        }
    }
}
