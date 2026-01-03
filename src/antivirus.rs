//! Anti-virus protection module.
//!
//! Implements attachment scanning and malware detection for emails.
//! Supports ClamAV integration when available, with built-in fallback scanning.

use base64::Engine;
use std::time::Duration;

/// Scan result for an email
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub is_infected: bool,
    pub threats: Vec<String>,
}

impl ScanResult {
    pub fn clean() -> Self {
        Self {
            is_infected: false,
            threats: Vec::new(),
        }
    }

    pub fn add_threat(&mut self, threat: String) {
        self.is_infected = true;
        self.threats.push(threat);
    }
}

/// ClamAV connection configuration
#[derive(Debug, Clone)]
pub struct ClamAVConfig {
    /// ClamAV server address (e.g., "127.0.0.1:3310" or "/var/run/clamav/clamd.sock")
    pub address: String,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
    /// Whether ClamAV is enabled
    pub enabled: bool,
}

impl Default for ClamAVConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:3310".to_string(),
            timeout_secs: 30,
            enabled: true,
        }
    }
}

/// Anti-virus scanner
#[derive(Debug)]
pub struct AntiVirus {
    /// Maximum attachment size in bytes (default: 10MB)
    pub max_attachment_size: usize,
    /// Maximum number of attachments
    pub max_attachments: usize,
    /// Blocked file extensions
    blocked_extensions: Vec<String>,
    /// Dangerous MIME types
    dangerous_mime_types: Vec<String>,
    /// Known malware signatures (hex patterns)
    malware_signatures: Vec<(&'static str, &'static str)>,
    /// ClamAV configuration
    clamav_config: ClamAVConfig,
    /// Whether ClamAV is available (checked on first scan)
    clamav_available: std::sync::atomic::AtomicBool,
    /// Whether we've checked ClamAV availability
    clamav_checked: std::sync::atomic::AtomicBool,
}

impl AntiVirus {
    pub fn new() -> Self {
        // Check for ClamAV address from environment
        let clamav_address =
            std::env::var("CLAMAV_ADDRESS").unwrap_or_else(|_| "127.0.0.1:3310".to_string());
        let clamav_enabled = std::env::var("CLAMAV_ENABLED")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);

        Self {
            max_attachment_size: 10 * 1024 * 1024, // 10MB
            max_attachments: 50,
            clamav_config: ClamAVConfig {
                address: clamav_address,
                timeout_secs: 30,
                enabled: clamav_enabled,
            },
            clamav_available: std::sync::atomic::AtomicBool::new(false),
            clamav_checked: std::sync::atomic::AtomicBool::new(false),
            blocked_extensions: vec![
                // Executables
                ".exe".into(),
                ".com".into(),
                ".cmd".into(),
                ".bat".into(),
                ".pif".into(),
                ".scr".into(),
                ".msi".into(),
                ".msp".into(),
                // Scripts
                ".js".into(),
                ".jse".into(),
                ".vbs".into(),
                ".vbe".into(),
                ".ws".into(),
                ".wsf".into(),
                ".wsc".into(),
                ".wsh".into(),
                ".ps1".into(),
                ".psm1".into(),
                ".psd1".into(),
                // Other dangerous
                ".hta".into(),
                ".cpl".into(),
                ".msc".into(),
                ".jar".into(),
                ".reg".into(),
                ".inf".into(),
                ".scf".into(),
                ".lnk".into(),
                ".prf".into(),
                ".prg".into(),
                ".crt".into(),
                // Office macros
                ".docm".into(),
                ".xlsm".into(),
                ".pptm".into(),
                ".dotm".into(),
                ".xltm".into(),
                ".potm".into(),
                ".xlam".into(),
                ".ppam".into(),
                ".sldm".into(),
                // Archives that can contain executables
                ".iso".into(),
                ".img".into(),
                ".vhd".into(),
                ".vhdx".into(),
            ],
            dangerous_mime_types: vec![
                "application/x-msdownload".into(),
                "application/x-msdos-program".into(),
                "application/x-executable".into(),
                "application/x-dosexec".into(),
                "application/hta".into(),
                "application/x-ms-shortcut".into(),
                "application/x-javascript".into(),
                "text/javascript".into(),
                "application/x-vbscript".into(),
                "application/x-powershell".into(),
            ],
            malware_signatures: vec![
                // PE executable header
                ("4D5A", "Windows executable (MZ header)"),
                // ELF executable header
                ("7F454C46", "Linux executable (ELF)"),
                // Mach-O executable headers
                ("CAFEBABE", "Java class/Mach-O fat binary"),
                ("FEEDFACE", "Mach-O 32-bit"),
                ("FEEDFACF", "Mach-O 64-bit"),
                // Shell script
                ("23212F62696E", "Shell script (#!/bin)"),
                ("23212F7573722F62696E", "Shell script (#!/usr/bin)"),
                // PowerShell indicators
                ("506F7765725368656C6C", "PowerShell script"),
                ("496E766F6B652D", "PowerShell Invoke- command"),
                // VBA/Macro indicators
                ("4174747269627574652056425F", "VBA macro (Attribute VB_)"),
                ("5375622041", "VBA Sub procedure"),
                ("46756E6374696F6E20", "VBA Function"),
                ("4175746F4F70656E", "AutoOpen macro"),
                ("4175746F45786563", "AutoExec macro"),
                ("446F63756D656E745F4F70656E", "Document_Open macro"),
                ("576F726B626F6F6B5F4F70656E", "Workbook_Open macro"),
                // EICAR test signature (for testing AV)
                (
                    "58354F2150254041505B345C505A58353428505E2937434329377D2445494341522D5354414E444152442D414E544956495255532D544553542D46494C452124482B482A",
                    "EICAR test file",
                ),
                // Common malware patterns
                ("636D642E657865202F63", "cmd.exe /c execution"),
                ("706F7765727368656C6C202D", "PowerShell execution"),
                ("7773637269707420", "WScript execution"),
                ("6373637269707420", "CScript execution"),
                // Base64 encoded "cmd" and "powershell"
                ("59323168", "Base64 encoded 'cmd'"),
                (
                    "634739335A584A7A6147567362413D3D",
                    "Base64 encoded 'powershell'",
                ),
                // Registry manipulation
                ("5245475F535A", "Registry string value"),
                ("484B45595F", "Registry hive reference"),
                // Network indicators
                ("57696E48747470", "WinHTTP usage"),
                ("55524C446F776E6C6F616446696C65", "URLDownloadToFile"),
                // Ransomware indicators
                (
                    "596F75722066696C657320686176652062",
                    "Ransomware message pattern",
                ),
                ("456E637279707465642077697468", "Encryption notice"),
            ],
        }
    }

    /// Scan an email for viruses and malicious content
    pub fn scan(&self, raw_email: &str) -> ScanResult {
        // Try async ClamAV scan in a blocking context if available
        let clamav_result = self.try_clamav_scan(raw_email.as_bytes());

        // Run built-in scan
        let mut result = self.builtin_scan(raw_email);

        // Merge ClamAV results if we got any
        if let Some(clamav_threats) = clamav_result {
            for threat in clamav_threats {
                result.add_threat(format!("ClamAV: {}", threat));
            }
        }

        if result.is_infected {
            tracing::warn!("Virus scan detected threats: {:?}", result.threats);
        }

        result
    }

    /// Try to scan with ClamAV, returns None if ClamAV unavailable
    fn try_clamav_scan(&self, data: &[u8]) -> Option<Vec<String>> {
        if !self.clamav_config.enabled {
            return None;
        }

        // Check if we've already determined ClamAV is unavailable
        if self
            .clamav_checked
            .load(std::sync::atomic::Ordering::Relaxed)
            && !self
                .clamav_available
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            return None;
        }

        // Try to connect and scan
        match self.clamav_scan_sync(data) {
            Ok(threats) => {
                self.clamav_checked
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                self.clamav_available
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                if threats.is_empty() {
                    None
                } else {
                    Some(threats)
                }
            }
            Err(e) => {
                // Only log once when we first detect ClamAV is unavailable
                if !self
                    .clamav_checked
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    tracing::info!("ClamAV not available ({}), using built-in scanner", e);
                    self.clamav_checked
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    self.clamav_available
                        .store(false, std::sync::atomic::Ordering::Relaxed);
                }
                None
            }
        }
    }

    /// Synchronous ClamAV scan using TCP connection
    fn clamav_scan_sync(&self, data: &[u8]) -> Result<Vec<String>, String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let timeout = Duration::from_secs(self.clamav_config.timeout_secs);

        // Connect to ClamAV
        let mut stream = TcpStream::connect(&self.clamav_config.address)
            .map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        // Send INSTREAM command
        stream
            .write_all(b"zINSTREAM\0")
            .map_err(|e| format!("Write failed: {}", e))?;

        // Send data in chunks (ClamAV protocol: 4-byte big-endian length + data)
        let chunk_size = 4096;
        for chunk in data.chunks(chunk_size) {
            let len = (chunk.len() as u32).to_be_bytes();
            stream
                .write_all(&len)
                .map_err(|e| format!("Write length failed: {}", e))?;
            stream
                .write_all(chunk)
                .map_err(|e| format!("Write chunk failed: {}", e))?;
        }

        // Send zero-length chunk to indicate end
        stream
            .write_all(&[0, 0, 0, 0])
            .map_err(|e| format!("Write end failed: {}", e))?;

        // Read response
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|e| format!("Read failed: {}", e))?;

        let response_str = String::from_utf8_lossy(&response);
        let response_str = response_str.trim_matches('\0').trim();

        // Parse response
        // Format: "stream: OK" or "stream: VirusName FOUND"
        let mut threats = Vec::new();

        for line in response_str.lines() {
            let line = line.trim();
            if line.ends_with("FOUND") {
                // Extract virus name
                if let Some(virus_part) = line.strip_suffix("FOUND") {
                    let virus_name = virus_part
                        .trim()
                        .strip_prefix("stream:")
                        .unwrap_or(virus_part)
                        .trim()
                        .to_string();
                    if !virus_name.is_empty() {
                        threats.push(virus_name);
                    }
                }
            } else if line.contains("ERROR") {
                return Err(format!("ClamAV error: {}", line));
            }
        }

        Ok(threats)
    }

    /// Check if ClamAV is available
    pub fn is_clamav_available(&self) -> bool {
        if !self.clamav_config.enabled {
            return false;
        }

        if self
            .clamav_checked
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return self
                .clamav_available
                .load(std::sync::atomic::Ordering::Relaxed);
        }

        // Try a PING command
        match self.clamav_ping() {
            Ok(_) => {
                self.clamav_checked
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                self.clamav_available
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.clamav_checked
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                self.clamav_available
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                false
            }
        }
    }

    /// Ping ClamAV to check if it's running
    fn clamav_ping(&self) -> Result<(), String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        let timeout = Duration::from_secs(5);

        let mut stream = TcpStream::connect(&self.clamav_config.address)
            .map_err(|e| format!("Connection failed: {}", e))?;

        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        stream
            .write_all(b"zPING\0")
            .map_err(|e| format!("Write failed: {}", e))?;

        let mut response = [0u8; 64];
        let n = stream
            .read(&mut response)
            .map_err(|e| format!("Read failed: {}", e))?;

        let response_str = String::from_utf8_lossy(&response[..n]);
        if response_str.contains("PONG") {
            Ok(())
        } else {
            Err("Invalid response".to_string())
        }
    }

    /// Get ClamAV version if available
    pub fn clamav_version(&self) -> Option<String> {
        use std::io::{Read, Write};
        use std::net::TcpStream;

        if !self.clamav_config.enabled {
            return None;
        }

        let timeout = Duration::from_secs(5);

        let mut stream = TcpStream::connect(&self.clamav_config.address).ok()?;
        stream.set_read_timeout(Some(timeout)).ok();
        stream.set_write_timeout(Some(timeout)).ok();

        stream.write_all(b"zVERSION\0").ok()?;

        let mut response = [0u8; 256];
        let n = stream.read(&mut response).ok()?;

        let version = String::from_utf8_lossy(&response[..n])
            .trim_matches('\0')
            .trim()
            .to_string();

        if version.is_empty() {
            None
        } else {
            Some(version)
        }
    }

    /// Built-in virus scan (pattern matching)
    fn builtin_scan(&self, raw_email: &str) -> ScanResult {
        let mut result = ScanResult::clean();

        // Parse MIME structure
        let attachments = self.extract_attachments(raw_email);

        // Check attachment count
        if attachments.len() > self.max_attachments {
            result.add_threat(format!(
                "Too many attachments: {} (max: {})",
                attachments.len(),
                self.max_attachments
            ));
        }

        for attachment in &attachments {
            // Check file extension
            self.check_extension(attachment, &mut result);

            // Check MIME type
            self.check_mime_type(attachment, &mut result);

            // Check attachment size
            self.check_size(attachment, &mut result);

            // Decode and scan content
            if let Some(content) = &attachment.decoded_content {
                self.scan_content(content, &attachment.filename, &mut result);
            }
        }

        // Check for suspicious patterns in the raw email
        self.check_suspicious_patterns(raw_email, &mut result);

        // Check for zip bombs and nested archives
        self.check_archive_threats(raw_email, &mut result);

        result
    }

    fn extract_attachments(&self, raw_email: &str) -> Vec<Attachment> {
        let mut attachments = Vec::new();
        let email_lower = raw_email.to_lowercase();

        // Find boundary for multipart messages
        let boundary = self.extract_boundary(&email_lower);

        if let Some(boundary) = boundary {
            // Split by boundary and process each part
            let parts: Vec<&str> = raw_email.split(&format!("--{}", boundary)).collect();

            for part in parts.iter().skip(1) {
                // Skip the closing boundary
                if part.trim().starts_with("--") {
                    continue;
                }

                if let Some(attachment) = self.parse_mime_part(part) {
                    attachments.push(attachment);
                }
            }
        } else {
            // Single part message - check if it has an attachment
            if let Some(attachment) = self.parse_mime_part(raw_email) {
                if attachment.is_attachment {
                    attachments.push(attachment);
                }
            }
        }

        attachments
    }

    #[allow(clippy::manual_strip)]
    fn extract_boundary(&self, email: &str) -> Option<String> {
        // Look for boundary in Content-Type header
        if let Some(ct_start) = email.find("content-type:") {
            let ct_section = &email[ct_start..];
            let ct_end = ct_section
                .find("\r\n\r\n")
                .or_else(|| ct_section.find("\n\n"))
                .unwrap_or(ct_section.len().min(500));
            let ct_header = &ct_section[..ct_end];

            if let Some(boundary_start) = ct_header.find("boundary=") {
                let after_boundary = &ct_header[boundary_start + 9..];
                let boundary = if after_boundary.starts_with('"') {
                    // Quoted boundary
                    after_boundary[1..]
                        .find('"')
                        .map(|end| &after_boundary[1..end + 1])
                } else {
                    // Unquoted boundary
                    after_boundary
                        .find(|c: char| c.is_whitespace() || c == ';')
                        .map(|end| &after_boundary[..end])
                        .or(Some(after_boundary.trim()))
                };

                return boundary.map(|b| b.trim_matches('"').to_string());
            }
        }
        None
    }

    fn parse_mime_part(&self, part: &str) -> Option<Attachment> {
        let part_lower = part.to_lowercase();

        // Check if this is an attachment
        let is_attachment = part_lower.contains("content-disposition: attachment")
            || part_lower.contains("content-disposition:attachment")
            || (part_lower.contains("filename=")
                && !part_lower.contains("content-type: text/plain"));

        // Extract filename
        let filename = self.extract_filename(part);

        // Extract content type
        let content_type = self.extract_content_type(&part_lower);

        // Extract and decode content
        let decoded_content = self.decode_content(part);

        // Calculate size
        let size = decoded_content.as_ref().map(|c| c.len()).unwrap_or(0);

        Some(Attachment {
            filename: filename.unwrap_or_default(),
            content_type: content_type.unwrap_or_default(),
            size,
            is_attachment,
            decoded_content,
        })
    }

    #[allow(clippy::manual_strip)]
    fn extract_filename(&self, part: &str) -> Option<String> {
        let part_lower = part.to_lowercase();

        // Try Content-Disposition filename
        if let Some(pos) = part_lower.find("filename=") {
            let after_filename = &part[pos + 9..];
            let filename = if after_filename.starts_with('"') {
                after_filename[1..]
                    .find('"')
                    .map(|end| &after_filename[1..end + 1])
            } else {
                after_filename
                    .find(|c: char| c.is_whitespace() || c == ';' || c == '\r' || c == '\n')
                    .map(|end| &after_filename[..end])
            };
            return filename.map(|f| f.to_string());
        }

        // Try Content-Type name parameter
        if let Some(pos) = part_lower.find("name=") {
            let after_name = &part[pos + 5..];
            let name = if after_name.starts_with('"') {
                after_name[1..].find('"').map(|end| &after_name[1..end + 1])
            } else {
                after_name
                    .find(|c: char| c.is_whitespace() || c == ';' || c == '\r' || c == '\n')
                    .map(|end| &after_name[..end])
            };
            return name.map(|n| n.to_string());
        }

        None
    }

    #[allow(clippy::manual_pattern_char_comparison)]
    fn extract_content_type(&self, part_lower: &str) -> Option<String> {
        if let Some(pos) = part_lower.find("content-type:") {
            let after_ct = &part_lower[pos + 13..];
            let ct_end = after_ct
                .find(|c: char| c == ';' || c == '\r' || c == '\n')
                .unwrap_or(after_ct.len().min(100));
            return Some(after_ct[..ct_end].trim().to_string());
        }
        None
    }

    fn decode_content(&self, part: &str) -> Option<Vec<u8>> {
        let part_lower = part.to_lowercase();

        // Find the body (after double newline)
        let body_start = part
            .find("\r\n\r\n")
            .map(|p| p + 4)
            .or_else(|| part.find("\n\n").map(|p| p + 2))?;

        let body = &part[body_start..];

        // Check encoding
        if part_lower.contains("content-transfer-encoding: base64")
            || part_lower.contains("content-transfer-encoding:base64")
        {
            // Decode base64
            let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();

            base64::engine::general_purpose::STANDARD
                .decode(&cleaned)
                .ok()
        } else {
            // Plain text or quoted-printable (treat as raw bytes)
            Some(body.as_bytes().to_vec())
        }
    }

    fn check_extension(&self, attachment: &Attachment, result: &mut ScanResult) {
        let filename_lower = attachment.filename.to_lowercase();

        // Check for blocked extensions
        for ext in &self.blocked_extensions {
            if filename_lower.ends_with(ext) {
                result.add_threat(format!(
                    "Blocked file extension: {} (file: {})",
                    ext, attachment.filename
                ));
                return;
            }
        }

        // Check for double extensions (e.g., .pdf.exe)
        let parts: Vec<&str> = filename_lower.split('.').collect();
        if parts.len() > 2 {
            let last_ext = format!(".{}", parts.last().unwrap_or(&""));
            if self.blocked_extensions.contains(&last_ext) {
                result.add_threat(format!(
                    "Suspicious double extension: {} (file: {})",
                    last_ext, attachment.filename
                ));
            }
        }

        // Check for Unicode tricks in filename
        if attachment.filename.chars().any(|c| {
            matches!(
                c,
                '\u{202E}' | // Right-to-left override
                '\u{200B}' | // Zero-width space
                '\u{200C}' | // Zero-width non-joiner
                '\u{200D}' | // Zero-width joiner
                '\u{FEFF}' // Zero-width no-break space
            )
        }) {
            result.add_threat(format!(
                "Suspicious Unicode in filename: {}",
                attachment.filename
            ));
        }
    }

    fn check_mime_type(&self, attachment: &Attachment, result: &mut ScanResult) {
        let content_type_lower = attachment.content_type.to_lowercase();

        for dangerous_type in &self.dangerous_mime_types {
            if content_type_lower.contains(dangerous_type) {
                result.add_threat(format!(
                    "Dangerous MIME type: {} (file: {})",
                    dangerous_type, attachment.filename
                ));
                return;
            }
        }

        // Check for MIME type / extension mismatch
        if !attachment.filename.is_empty() && !attachment.content_type.is_empty() {
            let filename_lower = attachment.filename.to_lowercase();

            // PDF should be application/pdf
            if filename_lower.ends_with(".pdf") && !content_type_lower.contains("pdf") {
                result.add_threat(format!(
                    "MIME type mismatch: {} claims to be PDF but has type {}",
                    attachment.filename, attachment.content_type
                ));
            }

            // Image files
            if (filename_lower.ends_with(".jpg")
                || filename_lower.ends_with(".jpeg")
                || filename_lower.ends_with(".png")
                || filename_lower.ends_with(".gif"))
                && !content_type_lower.contains("image")
            {
                result.add_threat(format!(
                    "MIME type mismatch: {} claims to be image but has type {}",
                    attachment.filename, attachment.content_type
                ));
            }
        }
    }

    fn check_size(&self, attachment: &Attachment, result: &mut ScanResult) {
        if attachment.size > self.max_attachment_size {
            result.add_threat(format!(
                "Attachment too large: {} bytes (max: {} bytes, file: {})",
                attachment.size, self.max_attachment_size, attachment.filename
            ));
        }
    }

    fn scan_content(&self, content: &[u8], filename: &str, result: &mut ScanResult) {
        // Convert to hex for signature matching
        let hex_content: String = content
            .iter()
            .take(8192) // Only scan first 8KB for signatures
            .map(|b| format!("{:02X}", b))
            .collect();

        // Check against malware signatures
        for (signature, name) in &self.malware_signatures {
            if hex_content.contains(signature) {
                result.add_threat(format!(
                    "Malware signature detected: {} (file: {})",
                    name, filename
                ));
            }
        }

        // Check for executable content in non-executable files
        let filename_lower = filename.to_lowercase();
        let is_supposed_to_be_safe = filename_lower.ends_with(".pdf")
            || filename_lower.ends_with(".doc")
            || filename_lower.ends_with(".docx")
            || filename_lower.ends_with(".txt")
            || filename_lower.ends_with(".jpg")
            || filename_lower.ends_with(".png");

        if is_supposed_to_be_safe {
            // Check for PE header (Windows executable)
            if content.len() >= 2 && content[0] == 0x4D && content[1] == 0x5A {
                result.add_threat(format!(
                    "Executable content hidden in {}: PE header detected",
                    filename
                ));
            }

            // Check for ELF header (Linux executable)
            if content.len() >= 4
                && content[0] == 0x7F
                && content[1] == 0x45
                && content[2] == 0x4C
                && content[3] == 0x46
            {
                result.add_threat(format!(
                    "Executable content hidden in {}: ELF header detected",
                    filename
                ));
            }
        }

        // Check for Office macros in Office documents
        if filename_lower.ends_with(".doc")
            || filename_lower.ends_with(".docx")
            || filename_lower.ends_with(".xls")
            || filename_lower.ends_with(".xlsx")
        {
            // Look for VBA project stream indicators
            if content.windows(4).any(|w| w == b"_VBA" || w == b"VBA_") {
                result.add_threat(format!(
                    "VBA macro detected in Office document: {}",
                    filename
                ));
            }
        }
    }

    fn check_suspicious_patterns(&self, raw_email: &str, result: &mut ScanResult) {
        let email_lower = raw_email.to_lowercase();

        // Check for obfuscated content
        if email_lower.contains("fromcharcode") {
            result.add_threat("JavaScript fromCharCode obfuscation detected".to_string());
        }

        if email_lower.contains("eval(") || email_lower.contains("eval (") {
            result.add_threat("JavaScript eval() detected".to_string());
        }

        // Check for encoded PowerShell
        if email_lower.contains("-encodedcommand") || email_lower.contains("-enc ") {
            result.add_threat("Encoded PowerShell command detected".to_string());
        }

        // Check for common exploit kit patterns
        if email_lower.contains("activexobject") {
            result.add_threat("ActiveX object instantiation detected".to_string());
        }

        if email_lower.contains("wscript.shell") || email_lower.contains("wshshell") {
            result.add_threat("WScript.Shell usage detected".to_string());
        }

        // Check for iframe injection (common in HTML emails)
        if email_lower.contains("<iframe") && email_lower.contains("src=") {
            // Check if it's hidden
            if email_lower.contains("width=\"0\"")
                || email_lower.contains("width='0'")
                || email_lower.contains("height=\"0\"")
                || email_lower.contains("height='0'")
                || email_lower.contains("display:none")
                || email_lower.contains("visibility:hidden")
            {
                result.add_threat("Hidden iframe detected".to_string());
            }
        }

        // Check for data URIs with executables
        if email_lower.contains("data:application/x-msdownload")
            || email_lower.contains("data:application/octet-stream")
        {
            result.add_threat("Suspicious data URI detected".to_string());
        }
    }

    fn check_archive_threats(&self, raw_email: &str, result: &mut ScanResult) {
        let email_lower = raw_email.to_lowercase();

        // Check for password-protected archives (often used to evade scanning)
        if (email_lower.contains(".zip")
            || email_lower.contains(".rar")
            || email_lower.contains(".7z"))
            && (email_lower.contains("password")
                || email_lower.contains("passwort")
                || email_lower.contains("contraseña"))
        {
            result
                .add_threat("Password-protected archive mentioned (potential evasion)".to_string());
        }

        // Check for deeply nested archives (zip bomb indicator)
        let archive_extensions = [".zip", ".rar", ".7z", ".tar", ".gz"];
        let archive_count: usize = archive_extensions
            .iter()
            .map(|ext| email_lower.matches(ext).count())
            .sum();

        if archive_count > 3 {
            result.add_threat(format!(
                "Multiple archive references detected: {} (potential zip bomb)",
                archive_count
            ));
        }
    }

    /// Set maximum attachment size
    pub fn set_max_attachment_size(&mut self, size: usize) {
        self.max_attachment_size = size;
    }

    /// Add a blocked extension
    pub fn add_blocked_extension(&mut self, ext: String) {
        let ext = if ext.starts_with('.') {
            ext.to_lowercase()
        } else {
            format!(".{}", ext.to_lowercase())
        };
        if !self.blocked_extensions.contains(&ext) {
            self.blocked_extensions.push(ext);
        }
    }

    /// Configure ClamAV connection
    pub fn set_clamav_address(&mut self, address: String) {
        self.clamav_config.address = address;
        // Reset availability check
        self.clamav_checked
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Enable or disable ClamAV
    pub fn set_clamav_enabled(&mut self, enabled: bool) {
        self.clamav_config.enabled = enabled;
    }

    /// Get scanner status info
    pub fn status(&self) -> ScannerStatus {
        let clamav_available = self.is_clamav_available();
        let clamav_version = if clamav_available {
            self.clamav_version()
        } else {
            None
        };

        ScannerStatus {
            builtin_enabled: true,
            clamav_enabled: self.clamav_config.enabled,
            clamav_available,
            clamav_address: self.clamav_config.address.clone(),
            clamav_version,
        }
    }
}

/// Scanner status information
#[derive(Debug, Clone)]
pub struct ScannerStatus {
    pub builtin_enabled: bool,
    pub clamav_enabled: bool,
    pub clamav_available: bool,
    pub clamav_address: String,
    pub clamav_version: Option<String>,
}

impl Default for AntiVirus {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents an email attachment
#[derive(Debug)]
struct Attachment {
    filename: String,
    content_type: String,
    size: usize,
    is_attachment: bool,
    decoded_content: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_email() {
        let av = AntiVirus::new();
        let result = av.scan(
            "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Hello\r\n\r\nHello, world!",
        );
        assert!(!result.is_infected);
    }

    #[test]
    fn test_exe_attachment() {
        let av = AntiVirus::new();
        let email = r#"From: sender@example.com
To: recipient@example.com
Subject: Check this out
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain

Please run the attached file.

--boundary123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="virus.exe"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQA==

--boundary123--
"#;
        let result = av.scan(email);
        assert!(result.is_infected);
        assert!(result.threats.iter().any(|t| t.contains(".exe")));
    }

    #[test]
    fn test_double_extension() {
        let av = AntiVirus::new();
        let email = r#"Content-Type: multipart/mixed; boundary="bound"

--bound
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="document.pdf.exe"

test content

--bound--
"#;
        let result = av.scan(email);
        assert!(result.is_infected);
        // The double extension .exe is caught by the blocked extension check
        assert!(result.threats.iter().any(|t| t.contains(".exe")));
    }

    #[test]
    fn test_eicar_detection() {
        let av = AntiVirus::new();
        // EICAR test string (standard AV test pattern)
        let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        let email = format!(
            "Content-Type: multipart/mixed; boundary=\"testbound\"\r\n\r\n--testbound\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"test.dat\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--testbound--",
            base64::engine::general_purpose::STANDARD.encode(eicar)
        );
        let result = av.scan(&email);
        assert!(result.is_infected);
        assert!(result.threats.iter().any(|t| t.contains("EICAR")));
    }
}
