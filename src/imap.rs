//! IMAP Server implementation.
//!
//! Implements RFC 3501 (Internet Message Access Protocol) with basic commands.

use crate::storage::Storage;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone, PartialEq)]
enum ImapState {
    NotAuthenticated,
    Authenticated,
    Selected,
}

#[derive(Debug)]
struct ImapSession {
    state: ImapState,
    username: Option<String>,
    selected_mailbox: Option<String>,
}

impl ImapSession {
    fn new() -> Self {
        Self {
            state: ImapState::NotAuthenticated,
            username: None,
            selected_mailbox: None,
        }
    }
}

pub struct ImapServer {
    storage: Arc<Storage>,
}

impl ImapServer {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub async fn run(&self, addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("IMAP server listening on {}", addr);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            tracing::info!("IMAP connection from {}", peer_addr);

            let storage = Arc::clone(&self.storage);

            tokio::spawn(async move {
                if let Err(e) = handle_imap_connection(socket, storage).await {
                    tracing::error!("IMAP connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_imap_connection(
    socket: TcpStream,
    storage: Arc<Storage>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut session = ImapSession::new();

    // Send greeting
    writer
        .write_all(b"* OK kiss-mail IMAP4rev1 server ready\r\n")
        .await?;

    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            break;
        }

        let line_trimmed = line.trim();
        tracing::debug!("IMAP <- {}", line_trimmed);

        let response = process_imap_command(line_trimmed, &mut session, &storage).await;

        for resp_line in response.lines() {
            tracing::debug!("IMAP -> {}", resp_line);
        }
        writer.write_all(response.as_bytes()).await?;

        // Check if LOGOUT was issued
        if line_trimmed.to_uppercase().contains(" LOGOUT") {
            break;
        }
    }

    Ok(())
}

async fn process_imap_command(line: &str, session: &mut ImapSession, storage: &Storage) -> String {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    if parts.len() < 2 {
        return "* BAD Invalid command\r\n".to_string();
    }

    let tag = parts[0];
    let cmd = parts[1].to_uppercase();
    let args = parts.get(2).copied().unwrap_or("");

    match cmd.as_str() {
        "CAPABILITY" => {
            format!(
                "* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n{} OK CAPABILITY completed\r\n",
                tag
            )
        }
        "NOOP" => format!("{} OK NOOP completed\r\n", tag),
        "LOGOUT" => {
            format!(
                "* BYE kiss-mail server logging out\r\n{} OK LOGOUT completed\r\n",
                tag
            )
        }
        "LOGIN" => {
            if session.state != ImapState::NotAuthenticated {
                return format!("{} NO Already authenticated\r\n", tag);
            }

            let login_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if login_parts.len() < 2 {
                return format!("{} BAD Missing arguments\r\n", tag);
            }

            let username = login_parts[0].trim_matches('"');
            let password = login_parts[1].trim_matches('"');

            // Auto-create user if doesn't exist (KISS approach)
            if !storage.user_exists(username).await {
                storage
                    .create_user(username.to_string(), password.to_string())
                    .await;
                let _ = storage.save().await;
            }

            if storage.authenticate(username, password).await {
                session.state = ImapState::Authenticated;
                session.username = Some(username.to_string());
                format!("{} OK LOGIN completed\r\n", tag)
            } else {
                format!("{} NO LOGIN failed\r\n", tag)
            }
        }
        "AUTHENTICATE" => {
            if args.to_uppercase().starts_with("PLAIN") {
                // For simplicity, we'll handle inline PLAIN auth
                format!(
                    "{} NO AUTHENTICATE PLAIN not fully implemented, use LOGIN\r\n",
                    tag
                )
            } else {
                format!("{} NO Unknown authentication mechanism\r\n", tag)
            }
        }
        "SELECT" | "EXAMINE" => {
            if session.state == ImapState::NotAuthenticated {
                return format!("{} NO Not authenticated\r\n", tag);
            }

            let mailbox_name = args.trim_matches('"');

            // We only support INBOX
            if mailbox_name.to_uppercase() != "INBOX" {
                return format!("{} NO Mailbox does not exist\r\n", tag);
            }

            if let Some(mailbox) = storage
                .get_mailbox(session.username.as_ref().unwrap())
                .await
            {
                session.state = ImapState::Selected;
                session.selected_mailbox = Some("INBOX".to_string());

                let emails = mailbox.get_active_emails();
                let exists = emails.len();
                let recent = emails.iter().filter(|e| !e.seen).count();
                let unseen = emails.iter().position(|e| !e.seen).map(|i| i + 1);

                let mut response = String::new();
                response.push_str(&format!("* {} EXISTS\r\n", exists));
                response.push_str(&format!("* {} RECENT\r\n", recent));
                response.push_str("* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n");
                response.push_str("* OK [PERMANENTFLAGS (\\Seen \\Deleted)] Limited flags\r\n");
                if let Some(first_unseen) = unseen {
                    response.push_str(&format!("* OK [UNSEEN {}] First unseen\r\n", first_unseen));
                }
                response.push_str(&format!(
                    "* OK [UIDVALIDITY {}] UIDs valid\r\n",
                    mailbox.uidvalidity
                ));
                response.push_str(&format!(
                    "* OK [UIDNEXT {}] Predicted next UID\r\n",
                    mailbox.uidnext
                ));

                let access = if cmd == "SELECT" {
                    "[READ-WRITE]"
                } else {
                    "[READ-ONLY]"
                };
                response.push_str(&format!("{} OK {} {} completed\r\n", tag, access, cmd));
                response
            } else {
                format!("{} NO Mailbox does not exist\r\n", tag)
            }
        }
        "LIST" => {
            if session.state == ImapState::NotAuthenticated {
                return format!("{} NO Not authenticated\r\n", tag);
            }

            let mut response = String::new();
            response.push_str("* LIST (\\HasNoChildren) \"/\" \"INBOX\"\r\n");
            response.push_str(&format!("{} OK LIST completed\r\n", tag));
            response
        }
        "LSUB" => {
            if session.state == ImapState::NotAuthenticated {
                return format!("{} NO Not authenticated\r\n", tag);
            }

            let mut response = String::new();
            response.push_str("* LSUB (\\HasNoChildren) \"/\" \"INBOX\"\r\n");
            response.push_str(&format!("{} OK LSUB completed\r\n", tag));
            response
        }
        "STATUS" => {
            if session.state == ImapState::NotAuthenticated {
                return format!("{} NO Not authenticated\r\n", tag);
            }

            let status_parts: Vec<&str> = args.splitn(2, ' ').collect();
            let mailbox_name = status_parts.first().unwrap_or(&"").trim_matches('"');

            if mailbox_name.to_uppercase() != "INBOX" {
                return format!("{} NO Mailbox does not exist\r\n", tag);
            }

            if let Some(mailbox) = storage
                .get_mailbox(session.username.as_ref().unwrap())
                .await
            {
                let emails = mailbox.get_active_emails();
                let messages = emails.len();
                let recent = emails.iter().filter(|e| !e.seen).count();
                let unseen = emails.iter().filter(|e| !e.seen).count();

                format!(
                    "* STATUS \"INBOX\" (MESSAGES {} RECENT {} UNSEEN {} UIDNEXT {} UIDVALIDITY {})\r\n{} OK STATUS completed\r\n",
                    messages, recent, unseen, mailbox.uidnext, mailbox.uidvalidity, tag
                )
            } else {
                format!("{} NO Mailbox does not exist\r\n", tag)
            }
        }
        "CREATE" | "DELETE" | "RENAME" | "SUBSCRIBE" | "UNSUBSCRIBE" => {
            // We only support INBOX, so these are no-ops or errors
            format!("{} NO Operation not supported\r\n", tag)
        }
        "CLOSE" => {
            if session.state != ImapState::Selected {
                return format!("{} NO No mailbox selected\r\n", tag);
            }

            // Expunge deleted messages
            storage.expunge(session.username.as_ref().unwrap()).await;
            let _ = storage.save().await;

            session.state = ImapState::Authenticated;
            session.selected_mailbox = None;
            format!("{} OK CLOSE completed\r\n", tag)
        }
        "EXPUNGE" => {
            if session.state != ImapState::Selected {
                return format!("{} NO No mailbox selected\r\n", tag);
            }

            let expunged = storage.expunge(session.username.as_ref().unwrap()).await;
            let _ = storage.save().await;

            let mut response = String::new();
            for seq in expunged {
                response.push_str(&format!("* {} EXPUNGE\r\n", seq));
            }
            response.push_str(&format!("{} OK EXPUNGE completed\r\n", tag));
            response
        }
        "SEARCH" => {
            if session.state != ImapState::Selected {
                return format!("{} NO No mailbox selected\r\n", tag);
            }

            if let Some(mailbox) = storage
                .get_mailbox(session.username.as_ref().unwrap())
                .await
            {
                let emails = mailbox.get_active_emails();
                let args_upper = args.to_uppercase();

                let matching: Vec<usize> = if args_upper.contains("ALL") {
                    (1..=emails.len()).collect()
                } else if args_upper.contains("UNSEEN") {
                    emails
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| !e.seen)
                        .map(|(i, _)| i + 1)
                        .collect()
                } else if args_upper.contains("SEEN") {
                    emails
                        .iter()
                        .enumerate()
                        .filter(|(_, e)| e.seen)
                        .map(|(i, _)| i + 1)
                        .collect()
                } else {
                    // Default to all
                    (1..=emails.len()).collect()
                };

                let seq_str: String = matching
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("* SEARCH {}\r\n{} OK SEARCH completed\r\n", seq_str, tag)
            } else {
                format!("{} NO Mailbox error\r\n", tag)
            }
        }
        "FETCH" => {
            if session.state != ImapState::Selected {
                return format!("{} NO No mailbox selected\r\n", tag);
            }

            let fetch_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if fetch_parts.len() < 2 {
                return format!("{} BAD Missing arguments\r\n", tag);
            }

            let sequence = fetch_parts[0];
            let items = fetch_parts[1];

            if let Some(mailbox) = storage
                .get_mailbox(session.username.as_ref().unwrap())
                .await
            {
                let emails = mailbox.get_active_emails();
                let seq_nums = parse_sequence_set(sequence, emails.len());

                let mut response = String::new();

                for seq in seq_nums {
                    if seq > 0 && seq <= emails.len() {
                        let email = &emails[seq - 1];
                        let fetch_response = build_fetch_response(seq, email, items);
                        response.push_str(&fetch_response);
                    }
                }

                response.push_str(&format!("{} OK FETCH completed\r\n", tag));
                response
            } else {
                format!("{} NO Mailbox error\r\n", tag)
            }
        }
        "STORE" => {
            if session.state != ImapState::Selected {
                return format!("{} NO No mailbox selected\r\n", tag);
            }

            let store_parts: Vec<&str> = args.splitn(3, ' ').collect();
            if store_parts.len() < 3 {
                return format!("{} BAD Missing arguments\r\n", tag);
            }

            let sequence = store_parts[0];
            let action = store_parts[1].to_uppercase();
            let flags = store_parts[2];

            if let Some(mailbox) = storage
                .get_mailbox(session.username.as_ref().unwrap())
                .await
            {
                let emails = mailbox.get_active_emails();
                let seq_nums = parse_sequence_set(sequence, emails.len());

                let mut response = String::new();

                for seq in &seq_nums {
                    if *seq > 0 && *seq <= emails.len() {
                        let flags_upper = flags.to_uppercase();

                        if flags_upper.contains("\\SEEN") && action.contains("+") {
                            storage
                                .mark_seen(session.username.as_ref().unwrap(), seq - 1)
                                .await;
                        }

                        if flags_upper.contains("\\DELETED") {
                            let deleted = action.contains("+");
                            storage
                                .mark_deleted(session.username.as_ref().unwrap(), seq - 1, deleted)
                                .await;
                        }

                        // Respond with updated flags
                        let email = &emails[*seq - 1];
                        let mut current_flags = Vec::new();
                        if email.seen {
                            current_flags.push("\\Seen");
                        }
                        if email.deleted {
                            current_flags.push("\\Deleted");
                        }

                        response.push_str(&format!(
                            "* {} FETCH (FLAGS ({}))\r\n",
                            seq,
                            current_flags.join(" ")
                        ));
                    }
                }

                let _ = storage.save().await;
                response.push_str(&format!("{} OK STORE completed\r\n", tag));
                response
            } else {
                format!("{} NO Mailbox error\r\n", tag)
            }
        }
        "COPY" => {
            // We only have one mailbox, so COPY doesn't make sense
            format!("{} NO COPY not supported\r\n", tag)
        }
        "UID" => {
            // UID variants of commands
            let uid_parts: Vec<&str> = args.splitn(2, ' ').collect();
            if uid_parts.is_empty() {
                return format!("{} BAD Missing UID command\r\n", tag);
            }

            let uid_cmd = uid_parts[0].to_uppercase();
            let _uid_args = uid_parts.get(1).copied().unwrap_or("");

            match uid_cmd.as_str() {
                "FETCH" | "SEARCH" | "STORE" | "COPY" => {
                    // For simplicity, handle UID commands similarly to regular commands
                    // In a full implementation, we'd use UIDs instead of sequence numbers
                    format!("{} OK UID {} completed (simplified)\r\n", tag, uid_cmd)
                }
                _ => format!("{} BAD Unknown UID command\r\n", tag),
            }
        }
        "CHECK" => {
            if session.state != ImapState::Selected {
                return format!("{} NO No mailbox selected\r\n", tag);
            }
            format!("{} OK CHECK completed\r\n", tag)
        }
        "IDLE" => {
            // IDLE extension - we'll just acknowledge it
            "+ idling\r\n".to_string()
        }
        _ => format!("{} BAD Unknown command\r\n", tag),
    }
}

fn parse_sequence_set(seq_str: &str, max: usize) -> Vec<usize> {
    let mut result = Vec::new();

    for part in seq_str.split(',') {
        let part = part.trim();
        if part.contains(':') {
            let range_parts: Vec<&str> = part.split(':').collect();
            if range_parts.len() == 2 {
                let start = if range_parts[0] == "*" {
                    max
                } else {
                    range_parts[0].parse().unwrap_or(1)
                };
                let end = if range_parts[1] == "*" {
                    max
                } else {
                    range_parts[1].parse().unwrap_or(max)
                };

                let (start, end) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };

                for i in start..=end {
                    if i <= max {
                        result.push(i);
                    }
                }
            }
        } else if part == "*" {
            result.push(max);
        } else if let Ok(num) = part.parse::<usize>() {
            if num <= max {
                result.push(num);
            }
        }
    }

    result
}

fn build_fetch_response(seq: usize, email: &crate::storage::Email, items: &str) -> String {
    let items_upper = items.to_uppercase();
    let mut parts = Vec::new();

    // Parse what's being requested
    let wants_flags = items_upper.contains("FLAGS");
    let wants_envelope = items_upper.contains("ENVELOPE");
    let wants_body = items_upper.contains("BODY")
        || items_upper.contains("RFC822")
        || items_upper.contains("ALL")
        || items_upper.contains("FULL");
    let wants_bodystructure = items_upper.contains("BODYSTRUCTURE");
    let wants_internaldate = items_upper.contains("INTERNALDATE");
    let wants_size = items_upper.contains("RFC822.SIZE") || items_upper.contains("ALL");
    let wants_uid = items_upper.contains("UID");
    let wants_header = items_upper.contains("HEADER") || items_upper.contains("RFC822.HEADER");

    if wants_flags {
        let mut flags = Vec::new();
        if email.seen {
            flags.push("\\Seen");
        }
        if email.deleted {
            flags.push("\\Deleted");
        }
        parts.push(format!("FLAGS ({})", flags.join(" ")));
    }

    if wants_uid {
        parts.push(format!("UID {}", seq)); // Simplified: using seq as UID
    }

    if wants_internaldate {
        let date = email.received_at.format("%d-%b-%Y %H:%M:%S %z");
        parts.push(format!("INTERNALDATE \"{}\"", date));
    }

    if wants_size {
        parts.push(format!("RFC822.SIZE {}", email.size));
    }

    if wants_envelope {
        let date = email.get_header("Date").unwrap_or("");
        let subject = &email.subject;
        let from = &email.from;
        let to = email.to.first().map(|s| s.as_str()).unwrap_or("");

        parts.push(format!(
            "ENVELOPE (\"{}\" \"{}\" ((NIL NIL \"{}\" NIL)) ((NIL NIL \"{}\" NIL)) ((NIL NIL \"{}\" NIL)) ((NIL NIL \"{}\" NIL)) NIL NIL NIL NIL)",
            date, subject, from, from, from, to
        ));
    }

    if wants_bodystructure {
        parts.push(
            "BODYSTRUCTURE (\"TEXT\" \"PLAIN\" (\"CHARSET\" \"UTF-8\") NIL NIL \"7BIT\" 0 0)"
                .to_string(),
        );
    }

    if wants_header {
        let header_end = email.raw.find("\r\n\r\n").unwrap_or(email.raw.len());
        let headers = &email.raw[..header_end];
        parts.push(format!(
            "RFC822.HEADER {{{}}}\r\n{}",
            headers.len(),
            headers
        ));
    }

    if wants_body {
        if items_upper.contains("BODY[]") || items_upper.contains("RFC822") {
            parts.push(format!("BODY[] {{{}}}\r\n{}", email.raw.len(), email.raw));
        } else if items_upper.contains("BODY[TEXT]") {
            parts.push(format!(
                "BODY[TEXT] {{{}}}\r\n{}",
                email.body.len(),
                email.body
            ));
        } else if items_upper.contains("BODY.PEEK") {
            // PEEK doesn't mark as seen
            if items_upper.contains("BODY.PEEK[]") {
                parts.push(format!("BODY[] {{{}}}\r\n{}", email.raw.len(), email.raw));
            } else if items_upper.contains("BODY.PEEK[HEADER]") {
                let header_end = email.raw.find("\r\n\r\n").unwrap_or(email.raw.len());
                let headers = &email.raw[..header_end];
                parts.push(format!("BODY[HEADER] {{{}}}\r\n{}", headers.len(), headers));
            }
        }
    }

    if parts.is_empty() {
        // Default response
        let mut flags = Vec::new();
        if email.seen {
            flags.push("\\Seen");
        }
        if email.deleted {
            flags.push("\\Deleted");
        }
        parts.push(format!("FLAGS ({})", flags.join(" ")));
    }

    format!("* {} FETCH ({})\r\n", seq, parts.join(" "))
}
