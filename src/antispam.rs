//! Anti-spam detection module.
//!
//! Implements a hybrid spam detection system combining:
//! - Rule-based scoring (heuristics)
//! - AI/Bayesian classification (learned patterns)

use crate::spam_ai::{SpamClassification, SpamClassifier};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Spam detection result
#[derive(Debug, Clone)]
pub struct SpamResult {
    /// Rule-based score
    pub score: f32,
    /// AI probability (0.0 - 1.0)
    pub ai_probability: f64,
    /// Combined spam determination
    pub is_spam: bool,
    /// Rule-based reasons
    pub reasons: Vec<String>,
    /// AI spam indicators
    pub ai_spam_indicators: Vec<(String, f64)>,
    /// AI ham indicators
    pub ai_ham_indicators: Vec<(String, f64)>,
    /// AI confidence
    pub ai_confidence: f64,
}

impl SpamResult {
    pub fn new() -> Self {
        Self {
            score: 0.0,
            ai_probability: 0.5,
            is_spam: false,
            reasons: Vec::new(),
            ai_spam_indicators: Vec::new(),
            ai_ham_indicators: Vec::new(),
            ai_confidence: 0.0,
        }
    }

    pub fn add_score(&mut self, points: f32, reason: &str) {
        self.score += points;
        if points > 0.0 {
            self.reasons.push(format!("{} (+{:.1})", reason, points));
        }
    }

    pub fn set_ai_classification(&mut self, classification: SpamClassification) {
        self.ai_probability = classification.spam_probability;
        self.ai_spam_indicators = classification.spam_indicators;
        self.ai_ham_indicators = classification.ham_indicators;
        self.ai_confidence = classification.confidence;
    }

    pub fn finalize(&mut self, rule_threshold: f32, ai_threshold: f64, ai_weight: f64) {
        // Combine rule-based and AI scores
        // - Rule score is normalized to 0-1 range (assuming max score of 10)
        // - AI probability is already 0-1
        // - Combined using weighted average
        
        let rule_normalized = (self.score / 10.0).clamp(0.0, 1.0) as f64;
        let combined = rule_normalized * (1.0 - ai_weight) + self.ai_probability * ai_weight;
        
        // Spam if:
        // 1. Combined score exceeds threshold, OR
        // 2. Rule score alone exceeds threshold (hard rules), OR
        // 3. AI is very confident it's spam (>0.9 with high confidence)
        self.is_spam = combined >= ai_threshold
            || self.score >= rule_threshold
            || (self.ai_probability > 0.9 && self.ai_confidence > 0.8);
    }
}

/// Rate limiter for tracking sender frequency
#[derive(Debug)]
struct RateLimitEntry {
    count: u32,
    first_seen: Instant,
}

/// Anti-spam checker
#[derive(Debug)]
pub struct AntiSpam {
    /// Rule-based spam score threshold (default: 5.0)
    pub threshold: f32,
    /// AI spam probability threshold (default: 0.7)
    pub ai_threshold: f64,
    /// Weight given to AI vs rules (0.0 = rules only, 1.0 = AI only, default: 0.6)
    pub ai_weight: f64,
    /// Rate limit window in seconds
    rate_limit_window: Duration,
    /// Max emails per window
    rate_limit_max: u32,
    /// Sender rate tracking
    rate_limits: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    /// Blocked keywords (case-insensitive)
    blocked_keywords: Vec<String>,
    /// Suspicious URL patterns
    suspicious_url_patterns: Vec<String>,
    /// AI spam classifier
    ai_classifier: Arc<SpamClassifier>,
}

impl AntiSpam {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            threshold: 5.0,
            ai_threshold: 0.7,
            ai_weight: 0.6, // 60% AI, 40% rules
            rate_limit_window: Duration::from_secs(60),
            rate_limit_max: 10,
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            ai_classifier: Arc::new(SpamClassifier::new(data_dir)),
            blocked_keywords: vec![
                // Common spam keywords
                "viagra".to_string(),
                "cialis".to_string(),
                "casino".to_string(),
                "lottery".to_string(),
                "winner".to_string(),
                "nigerian prince".to_string(),
                "wire transfer".to_string(),
                "bank account".to_string(),
                "credit card".to_string(),
                "act now".to_string(),
                "limited time".to_string(),
                "free money".to_string(),
                "make money fast".to_string(),
                "work from home".to_string(),
                "double your".to_string(),
                "million dollars".to_string(),
                "you have won".to_string(),
                "congratulations".to_string(),
                "claim your prize".to_string(),
                "urgent response".to_string(),
                "dear friend".to_string(),
                "100% free".to_string(),
                "no obligation".to_string(),
                "risk free".to_string(),
                "unsubscribe".to_string(),
            ],
            suspicious_url_patterns: vec![
                "bit.ly".to_string(),
                "tinyurl".to_string(),
                "t.co".to_string(),
                "goo.gl".to_string(),
                ".ru/".to_string(),
                ".cn/".to_string(),
                "click here".to_string(),
                "click now".to_string(),
            ],
        }
    }

    /// Load AI classifier data
    pub async fn load(&self) -> Result<(), std::io::Error> {
        self.ai_classifier.load().await
    }

    /// Save AI classifier data
    pub async fn save(&self) -> Result<(), std::io::Error> {
        self.ai_classifier.save().await
    }

    /// Check an email for spam indicators
    pub async fn check(&self, from: &str, to: &[String], raw_email: &str) -> SpamResult {
        let mut result = SpamResult::new();
        let raw_lower = raw_email.to_lowercase();

        // 1. AI Classification (Bayesian)
        let ai_classification = self.ai_classifier.classify(raw_email).await;
        result.set_ai_classification(ai_classification);

        // 2. Check rate limiting
        if self.check_rate_limit(from).await {
            result.add_score(3.0, "Rate limit exceeded");
        }

        // 3. Check sender address
        self.check_sender(from, &mut result);

        // 4. Check recipients
        self.check_recipients(to, &mut result);

        // 5. Check headers
        self.check_headers(raw_email, &mut result);

        // 6. Check content for spam keywords
        self.check_keywords(&raw_lower, &mut result);

        // 7. Check for suspicious URLs
        self.check_urls(&raw_lower, &mut result);

        // 8. Check formatting/structure
        self.check_structure(raw_email, &mut result);

        // 9. Check for common spam patterns
        self.check_patterns(&raw_lower, &mut result);

        // Finalize with combined rule + AI scoring
        result.finalize(self.threshold, self.ai_threshold, self.ai_weight);

        if result.is_spam {
            tracing::warn!(
                "Spam detected from {} (rules: {:.1}, AI: {:.1}%): {:?}",
                from,
                result.score,
                result.ai_probability * 100.0,
                result.reasons
            );
        } else {
            tracing::debug!(
                "Spam score for {}: rules={:.1}, AI={:.1}%",
                from,
                result.score,
                result.ai_probability * 100.0
            );
        }

        result
    }

    /// Train the AI classifier with a spam email
    pub async fn learn_spam(&self, email: &str) {
        self.ai_classifier.learn_spam(email).await;
        let _ = self.ai_classifier.save().await;
    }

    /// Train the AI classifier with a ham (non-spam) email
    pub async fn learn_ham(&self, email: &str) {
        self.ai_classifier.learn_ham(email).await;
        let _ = self.ai_classifier.save().await;
    }

    /// Get AI classifier statistics
    pub async fn ai_stats(&self) -> crate::spam_ai::ClassifierStats {
        self.ai_classifier.stats().await
    }

    async fn check_rate_limit(&self, sender: &str) -> bool {
        let sender_key = sender.to_lowercase();
        let mut limits = self.rate_limits.write().await;
        let now = Instant::now();

        // Clean up old entries
        limits.retain(|_, entry| now.duration_since(entry.first_seen) < self.rate_limit_window);

        if let Some(entry) = limits.get_mut(&sender_key) {
            if now.duration_since(entry.first_seen) < self.rate_limit_window {
                entry.count += 1;
                return entry.count > self.rate_limit_max;
            } else {
                // Reset window
                entry.count = 1;
                entry.first_seen = now;
            }
        } else {
            limits.insert(
                sender_key,
                RateLimitEntry {
                    count: 1,
                    first_seen: now,
                },
            );
        }

        false
    }

    fn check_sender(&self, from: &str, result: &mut SpamResult) {
        let from_lower = from.to_lowercase();

        // Empty sender
        if from.is_empty() {
            result.add_score(2.0, "Empty sender address");
        }

        // No @ in sender
        if !from.contains('@') {
            result.add_score(2.0, "Invalid sender format");
        }

        // Suspicious TLDs
        let suspicious_tlds = [".xyz", ".top", ".work", ".click", ".loan", ".racing"];
        for tld in &suspicious_tlds {
            if from_lower.ends_with(tld) {
                result.add_score(1.5, &format!("Suspicious TLD: {}", tld));
                break;
            }
        }

        // Numbers in domain (common in spam)
        if let Some(domain) = from_lower.split('@').nth(1) {
            let num_count = domain.chars().filter(|c| c.is_numeric()).count();
            if num_count > 3 {
                result.add_score(1.0, "Many numbers in sender domain");
            }
        }

        // Very long local part
        if let Some(local) = from.split('@').next() {
            if local.len() > 64 {
                result.add_score(1.0, "Unusually long sender local part");
            }
        }
    }

    fn check_recipients(&self, to: &[String], result: &mut SpamResult) {
        // Too many recipients
        if to.len() > 10 {
            result.add_score(2.0, "Too many recipients");
        }

        // Check for BCC indicators (recipients not in To/Cc headers)
        if to.is_empty() {
            result.add_score(1.5, "No recipients specified");
        }
    }

    fn check_headers(&self, raw: &str, result: &mut SpamResult) {
        let headers_end = raw.find("\r\n\r\n").or_else(|| raw.find("\n\n")).unwrap_or(raw.len());
        let headers = &raw[..headers_end].to_lowercase();

        // Missing common headers
        if !headers.contains("date:") {
            result.add_score(1.0, "Missing Date header");
        }
        if !headers.contains("message-id:") {
            result.add_score(0.5, "Missing Message-ID header");
        }
        if !headers.contains("subject:") {
            result.add_score(0.5, "Missing Subject header");
        }

        // Suspicious headers
        if headers.contains("x-mailer: phpmailer") {
            result.add_score(1.0, "PHPMailer detected");
        }
        if headers.contains("x-priority: 1") || headers.contains("importance: high") {
            result.add_score(0.5, "High priority flag");
        }

        // Multiple received headers from same host (potential relay)
        let received_count = headers.matches("received:").count();
        if received_count > 10 {
            result.add_score(1.0, "Excessive relay hops");
        }

        // Check for forged headers
        if headers.contains("x-originating-ip: 127.0.0.1") {
            result.add_score(1.5, "Suspicious originating IP");
        }
    }

    fn check_keywords(&self, content: &str, result: &mut SpamResult) {
        let mut keyword_hits = 0;

        for keyword in &self.blocked_keywords {
            if content.contains(keyword) {
                keyword_hits += 1;
                if keyword_hits <= 3 {
                    result.add_score(0.5, &format!("Spam keyword: {}", keyword));
                }
            }
        }

        // Additional penalty for multiple keyword hits
        if keyword_hits > 3 {
            result.add_score((keyword_hits - 3) as f32 * 0.3, "Multiple spam keywords");
        }
    }

    fn check_urls(&self, content: &str, result: &mut SpamResult) {
        // Count URLs
        let url_count = content.matches("http://").count() + content.matches("https://").count();

        if url_count > 5 {
            result.add_score(1.0, "Many URLs in message");
        }

        // Check for URL shorteners and suspicious patterns
        for pattern in &self.suspicious_url_patterns {
            if content.contains(pattern) {
                result.add_score(1.0, &format!("Suspicious URL pattern: {}", pattern));
            }
        }

        // IP-based URLs (common in phishing)
        if content.contains("http://192.")
            || content.contains("http://10.")
            || content.contains("http://172.")
        {
            result.add_score(2.0, "IP-based URL detected");
        }
    }

    fn check_structure(&self, raw: &str, result: &mut SpamResult) {
        // ALL CAPS subject
        if let Some(subject_start) = raw.to_lowercase().find("subject:") {
            let subject_line_end = raw[subject_start..]
                .find('\n')
                .map(|p| subject_start + p)
                .unwrap_or(raw.len());
            let subject = &raw[subject_start + 8..subject_line_end].trim();
            
            let caps_ratio = subject.chars().filter(|c| c.is_uppercase()).count() as f32
                / subject.chars().filter(|c| c.is_alphabetic()).count().max(1) as f32;
            
            if caps_ratio > 0.7 && subject.len() > 10 {
                result.add_score(1.0, "Subject mostly uppercase");
            }
        }

        // Check for excessive punctuation (!!!!, ????, etc)
        let exclamation_count = raw.matches('!').count();
        let question_count = raw.matches('?').count();
        let dollar_count = raw.matches('$').count();

        if exclamation_count > 5 {
            result.add_score(0.5, "Excessive exclamation marks");
        }
        if dollar_count > 3 {
            result.add_score(0.5, "Multiple dollar signs");
        }
        if question_count > 10 {
            result.add_score(0.3, "Many question marks");
        }

        // Very short body (typical of spam probes)
        let body_start = raw.find("\r\n\r\n").or_else(|| raw.find("\n\n"));
        if let Some(start) = body_start {
            let body = &raw[start..];
            if body.trim().len() < 20 && body.contains("http") {
                result.add_score(1.5, "Short body with URL");
            }
        }

        // HTML-only email (no text alternative)
        let content_lower = raw.to_lowercase();
        if content_lower.contains("content-type: text/html")
            && !content_lower.contains("content-type: text/plain")
            && !content_lower.contains("multipart/alternative")
        {
            result.add_score(0.5, "HTML-only email");
        }

        // Invisible/hidden text (common spam trick)
        if content_lower.contains("font-size:0")
            || content_lower.contains("font-size: 0")
            || content_lower.contains("display:none")
            || content_lower.contains("visibility:hidden")
        {
            result.add_score(2.0, "Hidden text detected");
        }
    }

    fn check_patterns(&self, content: &str, result: &mut SpamResult) {
        // Common spam phrases
        let spam_phrases = [
            ("dear valued customer", 1.5),
            ("verify your account", 1.5),
            ("suspended your account", 2.0),
            ("confirm your identity", 1.5),
            ("unusual activity", 1.0),
            ("click the link below", 1.0),
            ("act immediately", 1.0),
            ("your account will be", 1.0),
            ("within 24 hours", 0.5),
            ("within 48 hours", 0.5),
            ("you have been selected", 1.5),
            ("exclusive offer", 0.5),
            ("free gift", 1.0),
            ("no credit check", 1.5),
            ("as seen on", 0.5),
            ("order now", 0.5),
            ("supplies are limited", 0.5),
            ("what are you waiting for", 0.5),
            ("call now", 0.5),
            ("apply now", 0.5),
            ("increase your", 0.5),
            ("lower your", 0.5),
            ("eliminate debt", 1.5),
            ("refinance", 0.5),
            ("pharmacy", 1.0),
            ("prescription", 0.5),
        ];

        for (phrase, score) in &spam_phrases {
            if content.contains(phrase) {
                result.add_score(*score, &format!("Spam phrase: {}", phrase));
            }
        }

        // Base64 encoded executable attachments
        if content.contains("content-transfer-encoding: base64") {
            if content.contains(".exe")
                || content.contains(".scr")
                || content.contains(".bat")
                || content.contains(".cmd")
                || content.contains(".js\"")
                || content.contains(".vbs")
            {
                result.add_score(5.0, "Executable attachment detected");
            }
        }

        // Phishing patterns
        if (content.contains("paypal") || content.contains("amazon") || content.contains("apple") || content.contains("microsoft"))
            && (content.contains("verify") || content.contains("confirm") || content.contains("suspended"))
        {
            result.add_score(2.0, "Possible phishing attempt");
        }
    }

    /// Add a custom blocked keyword
    pub fn add_blocked_keyword(&mut self, keyword: String) {
        self.blocked_keywords.push(keyword.to_lowercase());
    }

    /// Set the rule-based spam threshold
    pub fn set_threshold(&mut self, threshold: f32) {
        self.threshold = threshold;
    }

    /// Set the AI spam probability threshold
    pub fn set_ai_threshold(&mut self, threshold: f64) {
        self.ai_threshold = threshold.clamp(0.0, 1.0);
    }

    /// Set the AI weight (0.0 = rules only, 1.0 = AI only)
    pub fn set_ai_weight(&mut self, weight: f64) {
        self.ai_weight = weight.clamp(0.0, 1.0);
    }

    /// Set rate limit parameters
    pub fn set_rate_limit(&mut self, max_per_window: u32, window_seconds: u64) {
        self.rate_limit_max = max_per_window;
        self.rate_limit_window = Duration::from_secs(window_seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_clean_email() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());
        let _ = antispam.load().await;
        
        let result = antispam
            .check(
                "user@example.com",
                &["recipient@example.com".to_string()],
                "From: user@example.com\r\nTo: recipient@example.com\r\nSubject: Hello\r\nDate: Mon, 1 Jan 2024 00:00:00 +0000\r\nMessage-ID: <123@example.com>\r\n\r\nHello, how are you?",
            )
            .await;
        
        assert!(!result.is_spam);
        assert!(result.score < 5.0);
    }

    #[tokio::test]
    async fn test_spam_email() {
        let dir = tempdir().unwrap();
        let antispam = AntiSpam::new(dir.path().to_path_buf());
        let _ = antispam.load().await;
        
        let result = antispam
            .check(
                "spammer@suspicious.xyz",
                &["victim@example.com".to_string()],
                "Subject: YOU HAVE WON!!!! CLAIM YOUR PRIZE NOW!!!!\r\n\r\nDear Friend,\r\n\r\nCongratulations! You have won the lottery! Click here to claim your million dollars: http://bit.ly/scam\r\n\r\nAct now! Limited time offer! Wire transfer required.",
            )
            .await;
        
        assert!(result.is_spam);
    }
}
