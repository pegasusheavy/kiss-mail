//! POP3 Server implementation.
//!
//! Implements RFC 1939 (Post Office Protocol - Version 3) with basic commands.

use crate::storage::Storage;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

const POP3_OK: &str = "+OK";
const POP3_ERR: &str = "-ERR";

#[derive(Debug, Clone, PartialEq)]
enum Pop3State {
    Authorization,
    Transaction,
}

#[derive(Debug)]
struct Pop3Session {
    state: Pop3State,
    username: Option<String>,
    deleted_messages: Vec<usize>,
}

impl Pop3Session {
    fn new() -> Self {
        Self {
            state: Pop3State::Authorization,
            username: None,
            deleted_messages: Vec::new(),
        }
    }
}

pub struct Pop3Server {
    storage: Arc<Storage>,
}

impl Pop3Server {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }

    pub async fn run(&self, addr: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("POP3 server listening on {}", addr);

        loop {
            let (socket, peer_addr) = listener.accept().await?;
            tracing::info!("POP3 connection from {}", peer_addr);

            let storage = Arc::clone(&self.storage);

            tokio::spawn(async move {
                if let Err(e) = handle_pop3_connection(socket, storage).await {
                    tracing::error!("POP3 connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_pop3_connection(
    socket: TcpStream,
    storage: Arc<Storage>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut session = Pop3Session::new();

    // Send greeting
    writer
        .write_all(format!("{} kiss-mail POP3 server ready\r\n", POP3_OK).as_bytes())
        .await?;

    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;

        if bytes_read == 0 {
            break;
        }

        let line_trimmed = line.trim();
        tracing::debug!("POP3 <- {}", line_trimmed);

        let response = process_pop3_command(line_trimmed, &mut session, &storage).await;

        for resp_line in response.lines() {
            tracing::debug!("POP3 -> {}", resp_line);
        }
        writer.write_all(response.as_bytes()).await?;

        if line_trimmed.to_uppercase().starts_with("QUIT") {
            break;
        }
    }

    Ok(())
}

async fn process_pop3_command(line: &str, session: &mut Pop3Session, storage: &Storage) -> String {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    let cmd = parts.first().map(|s| s.to_uppercase()).unwrap_or_default();

    match cmd.as_str() {
        "USER" => {
            if session.state != Pop3State::Authorization {
                return format!("{} Already authenticated\r\n", POP3_ERR);
            }
            if let Some(username) = parts.get(1) {
                session.username = Some(username.to_string());
                format!("{} User accepted\r\n", POP3_OK)
            } else {
                format!("{} Missing username\r\n", POP3_ERR)
            }
        }
        "PASS" => {
            if session.state != Pop3State::Authorization {
                return format!("{} Already authenticated\r\n", POP3_ERR);
            }
            if let (Some(username), Some(password)) = (&session.username, parts.get(1)) {
                if storage.authenticate(username, password).await {
                    session.state = Pop3State::Transaction;
                    format!("{} Logged in\r\n", POP3_OK)
                } else {
                    format!("{} Authentication failed\r\n", POP3_ERR)
                }
            } else {
                format!("{} USER first\r\n", POP3_ERR)
            }
        }
        "STAT" => {
            if session.state != Pop3State::Transaction {
                return format!("{} Not authenticated\r\n", POP3_ERR);
            }
            if let Some(mailbox) = storage
                .get_mailbox(session.username.as_ref().unwrap())
                .await
            {
                let emails = mailbox.get_active_emails();
                let count = emails.len();
                let size: usize = emails.iter().map(|e| e.size).sum();
                format!("{} {} {}\r\n", POP3_OK, count, size)
            } else {
                format!("{} Mailbox not found\r\n", POP3_ERR)
            }
        }
        "LIST" => {
            if session.state != Pop3State::Transaction {
                return format!("{} Not authenticated\r\n", POP3_ERR);
            }
            if let Some(mailbox) = storage
                .get_mailbox(session.username.as_ref().unwrap())
                .await
            {
                let emails = mailbox.get_active_emails();

                if let Some(msg_num) = parts.get(1) {
                    // Single message
                    if let Ok(num) = msg_num.parse::<usize>() {
                        if num > 0 && num <= emails.len() {
                            let email = &emails[num - 1];
                            format!("{} {} {}\r\n", POP3_OK, num, email.size)
                        } else {
                            format!("{} No such message\r\n", POP3_ERR)
                        }
                    } else {
                        format!("{} Invalid message number\r\n", POP3_ERR)
                    }
                } else {
                    // All messages
                    let mut response = format!("{} {} messages\r\n", POP3_OK, emails.len());
                    for (i, email) in emails.iter().enumerate() {
                        response.push_str(&format!("{} {}\r\n", i + 1, email.size));
                    }
                    response.push_str(".\r\n");
                    response
                }
            } else {
                format!("{} Mailbox not found\r\n", POP3_ERR)
            }
        }
        "RETR" => {
            if session.state != Pop3State::Transaction {
                return format!("{} Not authenticated\r\n", POP3_ERR);
            }
            if let Some(msg_num) = parts.get(1) {
                if let Ok(num) = msg_num.parse::<usize>() {
                    if let Some(mailbox) = storage
                        .get_mailbox(session.username.as_ref().unwrap())
                        .await
                    {
                        let emails = mailbox.get_active_emails();
                        if num > 0 && num <= emails.len() {
                            let email = &emails[num - 1];
                            let mut response = format!("{} {} octets\r\n", POP3_OK, email.size);
                            // Dot-stuff the message
                            for line in email.raw.lines() {
                                if line.starts_with('.') {
                                    response.push('.');
                                }
                                response.push_str(line);
                                response.push_str("\r\n");
                            }
                            response.push_str(".\r\n");
                            response
                        } else {
                            format!("{} No such message\r\n", POP3_ERR)
                        }
                    } else {
                        format!("{} Mailbox not found\r\n", POP3_ERR)
                    }
                } else {
                    format!("{} Invalid message number\r\n", POP3_ERR)
                }
            } else {
                format!("{} Missing message number\r\n", POP3_ERR)
            }
        }
        "DELE" => {
            if session.state != Pop3State::Transaction {
                return format!("{} Not authenticated\r\n", POP3_ERR);
            }
            if let Some(msg_num) = parts.get(1) {
                if let Ok(num) = msg_num.parse::<usize>() {
                    if let Some(mailbox) = storage
                        .get_mailbox(session.username.as_ref().unwrap())
                        .await
                    {
                        let emails = mailbox.get_active_emails();
                        if num > 0 && num <= emails.len() {
                            if !session.deleted_messages.contains(&num) {
                                session.deleted_messages.push(num);
                                storage
                                    .mark_deleted(session.username.as_ref().unwrap(), num - 1, true)
                                    .await;
                            }
                            format!("{} Message {} deleted\r\n", POP3_OK, num)
                        } else {
                            format!("{} No such message\r\n", POP3_ERR)
                        }
                    } else {
                        format!("{} Mailbox not found\r\n", POP3_ERR)
                    }
                } else {
                    format!("{} Invalid message number\r\n", POP3_ERR)
                }
            } else {
                format!("{} Missing message number\r\n", POP3_ERR)
            }
        }
        "RSET" => {
            if session.state != Pop3State::Transaction {
                return format!("{} Not authenticated\r\n", POP3_ERR);
            }
            // Undelete all messages
            for &num in &session.deleted_messages {
                storage
                    .mark_deleted(session.username.as_ref().unwrap(), num - 1, false)
                    .await;
            }
            session.deleted_messages.clear();
            format!("{} Maildrop reset\r\n", POP3_OK)
        }
        "NOOP" => format!("{}\r\n", POP3_OK),
        "QUIT" => {
            if session.state == Pop3State::Transaction {
                // Commit deletions
                storage.expunge(session.username.as_ref().unwrap()).await;
                let _ = storage.save().await;
            }
            format!("{} Bye\r\n", POP3_OK)
        }
        "UIDL" => {
            if session.state != Pop3State::Transaction {
                return format!("{} Not authenticated\r\n", POP3_ERR);
            }
            if let Some(mailbox) = storage
                .get_mailbox(session.username.as_ref().unwrap())
                .await
            {
                let emails = mailbox.get_active_emails();

                if let Some(msg_num) = parts.get(1) {
                    // Single message
                    if let Ok(num) = msg_num.parse::<usize>() {
                        if num > 0 && num <= emails.len() {
                            let email = &emails[num - 1];
                            format!("{} {} {}\r\n", POP3_OK, num, email.id)
                        } else {
                            format!("{} No such message\r\n", POP3_ERR)
                        }
                    } else {
                        format!("{} Invalid message number\r\n", POP3_ERR)
                    }
                } else {
                    // All messages
                    let mut response = format!("{}\r\n", POP3_OK);
                    for (i, email) in emails.iter().enumerate() {
                        response.push_str(&format!("{} {}\r\n", i + 1, email.id));
                    }
                    response.push_str(".\r\n");
                    response
                }
            } else {
                format!("{} Mailbox not found\r\n", POP3_ERR)
            }
        }
        "TOP" => {
            if session.state != Pop3State::Transaction {
                return format!("{} Not authenticated\r\n", POP3_ERR);
            }
            if let (Some(msg_num), Some(lines)) = (parts.get(1), parts.get(2)) {
                if let (Ok(num), Ok(line_count)) =
                    (msg_num.parse::<usize>(), lines.parse::<usize>())
                {
                    if let Some(mailbox) = storage
                        .get_mailbox(session.username.as_ref().unwrap())
                        .await
                    {
                        let emails = mailbox.get_active_emails();
                        if num > 0 && num <= emails.len() {
                            let email = &emails[num - 1];
                            let mut response = format!("{}\r\n", POP3_OK);

                            let mut in_body = false;
                            let mut body_lines = 0;

                            for line in email.raw.lines() {
                                if in_body {
                                    if body_lines >= line_count {
                                        break;
                                    }
                                    body_lines += 1;
                                } else if line.is_empty() {
                                    in_body = true;
                                }

                                if line.starts_with('.') {
                                    response.push('.');
                                }
                                response.push_str(line);
                                response.push_str("\r\n");
                            }
                            response.push_str(".\r\n");
                            response
                        } else {
                            format!("{} No such message\r\n", POP3_ERR)
                        }
                    } else {
                        format!("{} Mailbox not found\r\n", POP3_ERR)
                    }
                } else {
                    format!("{} Invalid arguments\r\n", POP3_ERR)
                }
            } else {
                format!("{} Missing arguments\r\n", POP3_ERR)
            }
        }
        "CAPA" => {
            let mut response = format!("{} Capability list follows\r\n", POP3_OK);
            response.push_str("USER\r\n");
            response.push_str("UIDL\r\n");
            response.push_str("TOP\r\n");
            response.push_str(".\r\n");
            response
        }
        _ => format!("{} Unknown command\r\n", POP3_ERR),
    }
}
