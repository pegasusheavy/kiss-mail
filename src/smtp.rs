//! SMTP Server implementation.
//!
//! Implements RFC 5321 (Simple Mail Transfer Protocol) with basic commands.

use crate::antispam::AntiSpam;
use crate::antivirus::AntiVirus;
use crate::groups::GroupManager;
use crate::storage::{Email, Storage};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const SMTP_BANNER: &str = "220 kiss-mail ESMTP ready";
const SMTP_OK: &str = "250 OK";
const SMTP_BYE: &str = "221 Bye";
const SMTP_START_DATA: &str = "354 Start mail input; end with <CRLF>.<CRLF>";
const SMTP_SYNTAX_ERROR: &str = "500 Syntax error, command unrecognized";
const SMTP_BAD_SEQUENCE: &str = "503 Bad sequence of commands";

#[derive(Debug, Default)]
struct SmtpSession {
    helo_domain: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    authenticated: bool,
    auth_username: Option<String>,
}

impl SmtpSession {
    fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
    }
}

pub struct SmtpServer {
    storage: Arc<Storage>,
    groups: Arc<GroupManager>,
    antispam: Arc<AntiSpam>,
    antivirus: Arc<AntiVirus>,
    hostname: String,
}

impl SmtpServer {
    pub fn new(
        storage: Arc<Storage>,
        groups: Arc<GroupManager>,
        antispam: Arc<AntiSpam>,
        antivirus: Arc<AntiVirus>,
        hostname: String,
    ) -> Self {
        Self {
            storage,
            groups,
            antispam,
            antivirus,
            hostname,
        }
    }

    pub async fn run(&self, addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("SMTP server listening on {}", addr);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            tracing::info!("SMTP connection from {}", peer_addr);

            let storage = Arc::clone(&self.storage);
            let groups = Arc::clone(&self.groups);
            let antispam = Arc::clone(&self.antispam);
            let antivirus = Arc::clone(&self.antivirus);
            let hostname = self.hostname.clone();

            tokio::spawn(async move {
                if let Err(e) =
                    handle_smtp_connection(socket, storage, groups, antispam, antivirus, hostname)
                        .await
                {
                    tracing::error!("SMTP connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_smtp_connection(
    socket: TcpStream,
    storage: Arc<Storage>,
    groups: Arc<GroupManager>,
    antispam: Arc<AntiSpam>,
    antivirus: Arc<AntiVirus>,
    hostname: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut session = SmtpSession::default();

    // Send banner
    writer
        .write_all(format!("{}\r\n", SMTP_BANNER).as_bytes())
        .await?;

    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            break;
        }

        let line = line.trim();
        tracing::debug!("SMTP <- {}", line);

        let response = process_smtp_command(line, &mut session, &storage, &hostname).await;

        tracing::debug!("SMTP -> {}", response);
        writer
            .write_all(format!("{}\r\n", response).as_bytes())
            .await?;

        if response.starts_with("221") {
            break;
        }

        // Handle DATA command
        if response.starts_with("354") {
            let data = read_data(&mut reader).await?;

            // Check for viruses first (more critical)
            let virus_result = antivirus.scan(&data);
            if virus_result.is_infected {
                tracing::warn!(
                    "Rejected infected email from {}: {:?}",
                    session.mail_from.as_deref().unwrap_or("unknown"),
                    virus_result.threats
                );
                writer
                    .write_all(
                        format!(
                            "550 Message rejected: malware detected ({})\r\n",
                            virus_result
                                .threats
                                .first()
                                .unwrap_or(&"unknown threat".to_string())
                        )
                        .as_bytes(),
                    )
                    .await?;
                session.reset();
                continue;
            }

            // Check for spam
            let spam_result = antispam
                .check(
                    session.mail_from.as_deref().unwrap_or(""),
                    &session.rcpt_to,
                    &data,
                )
                .await;

            if spam_result.is_spam {
                tracing::warn!(
                    "Rejected spam email from {} (score: {:.1})",
                    session.mail_from.as_deref().unwrap_or("unknown"),
                    spam_result.score
                );
                writer
                    .write_all(
                        format!(
                            "550 Message rejected as spam (score: {:.1})\r\n",
                            spam_result.score
                        )
                        .as_bytes(),
                    )
                    .await?;
                session.reset();
                continue;
            }

            // Add security headers to email
            let data_with_headers = add_security_headers(&data, &spam_result, &virus_result);

            // Expand group recipients
            let mut final_recipients: Vec<String> = Vec::new();
            for rcpt in &session.rcpt_to {
                // Check if this is a group email
                if let Some(members) = groups.expand_recipients(rcpt).await {
                    tracing::info!("Expanding group {} to {} members", rcpt, members.len());
                    for member in members {
                        if !final_recipients.contains(&member) {
                            final_recipients.push(member);
                        }
                    }
                } else {
                    // Regular recipient
                    if !final_recipients.contains(rcpt) {
                        final_recipients.push(rcpt.clone());
                    }
                }
            }

            let email = Email::new(
                session.mail_from.clone().unwrap_or_default(),
                final_recipients.clone(),
                data_with_headers,
            );

            // Deliver to all recipients (including expanded group members)
            for rcpt in &final_recipients {
                if let Err(e) = storage.deliver_email(rcpt, email.clone()).await {
                    tracing::error!("Failed to deliver to {}: {}", rcpt, e);
                }
            }

            // Save storage
            if let Err(e) = storage.save().await {
                tracing::error!("Failed to save storage: {}", e);
            }

            session.reset();

            writer.write_all(b"250 Message accepted\r\n").await?;
        }
    }

    Ok(())
}

/// Add security scan headers to email
fn add_security_headers(
    data: &str,
    spam_result: &crate::antispam::SpamResult,
    virus_result: &crate::antivirus::ScanResult,
) -> String {
    let header = format!(
        "X-Spam-Score: {:.1}\r\nX-Spam-Status: {}\r\nX-Virus-Scanned: kiss-mail\r\nX-Virus-Status: {}\r\n",
        spam_result.score,
        if spam_result.is_spam { "Yes" } else { "No" },
        if virus_result.is_infected {
            "Infected"
        } else {
            "Clean"
        }
    );

    // Insert after first line (usually "Received:" or start of headers)
    if let Some(first_newline) = data.find("\r\n") {
        format!(
            "{}{}{}",
            &data[..first_newline + 2],
            header,
            &data[first_newline + 2..]
        )
    } else if let Some(first_newline) = data.find('\n') {
        format!(
            "{}{}{}",
            &data[..first_newline + 1],
            header,
            &data[first_newline + 1..]
        )
    } else {
        format!("{}{}", header, data)
    }
}

async fn process_smtp_command(
    line: &str,
    session: &mut SmtpSession,
    storage: &Storage,
    hostname: &str,
) -> String {
    let upper = line.to_uppercase();
    let parts: Vec<&str> = line.splitn(2, ' ').collect();
    let cmd = parts.first().map(|s| s.to_uppercase()).unwrap_or_default();

    match cmd.as_str() {
        "HELO" => {
            if let Some(domain) = parts.get(1) {
                session.helo_domain = Some(domain.to_string());
                format!("250 {} Hello {}", hostname, domain)
            } else {
                SMTP_SYNTAX_ERROR.to_string()
            }
        }
        "EHLO" => {
            if let Some(domain) = parts.get(1) {
                session.helo_domain = Some(domain.to_string());
                format!(
                    "250-{} Hello {}\r\n250-SIZE 10485760\r\n250-8BITMIME\r\n250-AUTH PLAIN LOGIN\r\n250 OK",
                    hostname, domain
                )
            } else {
                SMTP_SYNTAX_ERROR.to_string()
            }
        }
        "AUTH" => {
            if let Some(args) = parts.get(1) {
                let auth_parts: Vec<&str> = args.splitn(2, ' ').collect();
                match auth_parts.first().map(|s| s.to_uppercase()).as_deref() {
                    Some("PLAIN") => {
                        if let Some(credentials) = auth_parts.get(1) {
                            match handle_auth_plain(credentials, storage).await {
                                Some(username) => {
                                    session.authenticated = true;
                                    session.auth_username = Some(username);
                                    "235 Authentication successful".to_string()
                                }
                                None => "535 Authentication failed".to_string(),
                            }
                        } else {
                            "334 ".to_string() // Request credentials
                        }
                    }
                    Some("LOGIN") => "334 VXNlcm5hbWU6".to_string(), // "Username:" in base64
                    _ => "504 Unrecognized authentication type".to_string(),
                }
            } else {
                SMTP_SYNTAX_ERROR.to_string()
            }
        }
        "MAIL" => {
            if session.helo_domain.is_none() {
                return SMTP_BAD_SEQUENCE.to_string();
            }

            if upper.starts_with("MAIL FROM:") {
                let from = extract_address(&line[10..]);
                session.mail_from = Some(from);
                SMTP_OK.to_string()
            } else {
                SMTP_SYNTAX_ERROR.to_string()
            }
        }
        "RCPT" => {
            if session.mail_from.is_none() {
                return SMTP_BAD_SEQUENCE.to_string();
            }

            if upper.starts_with("RCPT TO:") {
                let to = extract_address(&line[8..]);
                session.rcpt_to.push(to);
                SMTP_OK.to_string()
            } else {
                SMTP_SYNTAX_ERROR.to_string()
            }
        }
        "DATA" => {
            if session.rcpt_to.is_empty() {
                SMTP_BAD_SEQUENCE.to_string()
            } else {
                SMTP_START_DATA.to_string()
            }
        }
        "RSET" => {
            session.reset();
            SMTP_OK.to_string()
        }
        "NOOP" => SMTP_OK.to_string(),
        "QUIT" => SMTP_BYE.to_string(),
        "VRFY" => "252 Cannot VRFY user, but will accept message".to_string(),
        _ => SMTP_SYNTAX_ERROR.to_string(),
    }
}

fn extract_address(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('<') && s.contains('>') {
        let end = s.find('>').unwrap();
        s[1..end].to_string()
    } else {
        s.split_whitespace().next().unwrap_or(s).to_string()
    }
}

async fn read_data(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Result<String, std::io::Error> {
    let mut data = String::new();
    let mut line = String::new();

    loop {
        line.clear();
        reader.read_line(&mut line).await?;

        if line.trim() == "." {
            break;
        }

        // Handle dot-stuffing (RFC 5321 section 4.5.2)
        if line.starts_with("..") {
            data.push_str(&line[1..]);
        } else {
            data.push_str(&line);
        }
    }

    Ok(data)
}

async fn handle_auth_plain(credentials: &str, storage: &Storage) -> Option<String> {
    // PLAIN auth format: \0username\0password (base64 encoded)
    let decoded =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, credentials).ok()?;
    let parts: Vec<&[u8]> = decoded.split(|&b| b == 0).collect();

    if parts.len() >= 3 {
        let username = String::from_utf8_lossy(parts[1]);
        let password = String::from_utf8_lossy(parts[2]);

        if storage.authenticate(&username, &password).await {
            return Some(username.to_string());
        }
    }

    None
}
