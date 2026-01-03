//! KISS Mail Server
//!
//! A dead-simple SMTP, IMAP, and POP3 mail server.
//! Just run it. That's it.

// Allow dead code for public API items that may be used by external consumers
// or are reserved for future features
#![allow(dead_code)]

mod admin;
mod admin_api;
mod admin_web;
mod antispam;
mod antivirus;
mod crypto;
mod groups;
mod imap;
mod ldap;
mod pop3;
mod smtp;
mod spam_ai;
mod sso;
mod storage;
mod users;

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use admin::{AdminHandler, format_result};
use admin_api::{AdminApiConfig, ApiState, RemoteClient};
use admin_web::WebAdminConfig;
use antispam::AntiSpam;
use antivirus::AntiVirus;
use groups::GroupManager;
use ldap::LdapClient;
use sso::SsoManager;
use storage::Storage;
use users::{UserManager, UserRole};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Handle CLI commands
    if args.len() > 1 {
        return handle_cli(&args).await;
    }

    // Start the server
    run_server().await
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    // Simple logging
    tracing_subscriber::fmt()
        .with_env_filter("kiss_mail=info")
        .init();

    // Use current directory for data, or KISS_MAIL_DATA if set
    let data_dir = env::var("KISS_MAIL_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./mail_data"));

    // Auto-detect domain from hostname or use localhost
    let domain = env::var("KISS_MAIL_DOMAIN")
        .ok()
        .or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
        .unwrap_or_else(|| "localhost".to_string());

    // Initialize LDAP (needed for storage auth)
    let ldap_client = Arc::new(LdapClient::from_env());

    // Initialize SSO early (needed for app password auth in storage)
    let sso_manager = Arc::new(SsoManager::from_env(data_dir.clone()));
    if let Err(e) = sso_manager.load().await {
        tracing::warn!("Could not load SSO data: {}", e);
    }

    // Initialize encryption manager (ProtonMail-style zero-knowledge encryption)
    let crypto_manager = Arc::new(crypto::CryptoManager::new(data_dir.clone()));

    // Initialize user manager
    let user_manager = Arc::new(UserManager::new(domain.clone(), data_dir.clone()));
    let _ = user_manager.load().await;

    // Create storage with encryption support
    let storage = Arc::new(Storage::with_encryption(
        data_dir.clone(),
        Arc::clone(&user_manager),
        Arc::clone(&ldap_client),
        Arc::clone(&sso_manager),
        Arc::clone(&crypto_manager),
    ));
    let _ = storage.load().await;

    // Auto-create admin on first run
    let first_run = !user_manager.user_exists("admin").await;
    if first_run {
        let password = generate_simple_password();
        let _ = user_manager
            .create_user("admin", &password, Some(UserRole::SuperAdmin))
            .await;
        let _ = user_manager.save().await;

        println!();
        println!("🎉 First run detected! Created admin account:");
        println!("   Username: admin");
        println!("   Password: {}", password);
        println!();
        println!("   ⚠️  Save this password! You can change it with:");
        println!("      kiss-mail passwd admin <new-password>");
        println!();
    }

    // Ports - use standard ports if root, high ports otherwise
    let is_root = unsafe { libc::getuid() } == 0;
    let (smtp_port, imap_port, pop3_port) = if is_root {
        (25, 143, 110)
    } else {
        (2525, 1143, 1100)
    };

    // Allow env override
    let smtp_port = env::var("SMTP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(smtp_port);
    let imap_port = env::var("IMAP_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(imap_port);
    let pop3_port = env::var("POP3_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(pop3_port);

    // Initialize groups
    let group_manager = Arc::new(GroupManager::new(data_dir.clone()));
    if let Err(e) = group_manager.load().await {
        tracing::warn!("Could not load groups: {}", e);
    }

    // Test LDAP connection if enabled
    if ldap_client.is_enabled() {
        match ldap_client.test_connection().await {
            Ok(msg) => tracing::info!("LDAP: {}", msg),
            Err(e) => tracing::warn!("LDAP connection test failed: {}", e),
        }
    }

    // Log SSO status
    if sso_manager.is_enabled() {
        let status = sso_manager.status();
        tracing::info!("SSO: {} enabled", status.provider_name);
    }

    // Initialize spam detection (with AI)
    let antispam = Arc::new(AntiSpam::new(data_dir.clone()));
    if let Err(e) = antispam.load().await {
        tracing::warn!("Could not load spam classifier: {}", e);
    }

    let antivirus = Arc::new(AntiVirus::new());

    let smtp_server = smtp::SmtpServer::new(
        Arc::clone(&storage),
        Arc::clone(&group_manager),
        Arc::clone(&antispam),
        Arc::clone(&antivirus),
        domain.clone(),
    );
    let imap_server = imap::ImapServer::new(Arc::clone(&storage));
    let pop3_server = pop3::Pop3Server::new(Arc::clone(&storage));

    let smtp_addr = format!("0.0.0.0:{}", smtp_port);
    let imap_addr = format!("0.0.0.0:{}", imap_port);
    let pop3_addr = format!("0.0.0.0:{}", pop3_port);

    // Admin API configuration
    let api_config = AdminApiConfig::from_env();
    let api_port = api_config.port;
    let api_enabled = api_config.enabled;

    // Web admin configuration
    let web_config = WebAdminConfig::default();
    let web_port = web_config.port;
    let web_enabled = web_config.enabled;

    // Print startup info
    print_banner(
        &domain,
        smtp_port,
        imap_port,
        pop3_port,
        api_port,
        api_enabled,
        web_port,
        web_enabled,
        &user_manager,
        &group_manager,
        &ldap_client,
        &sso_manager,
        &antispam,
        &antivirus,
        &crypto_manager,
    )
    .await;

    // Create API state
    let api_state = ApiState {
        user_manager: Arc::clone(&user_manager),
        group_manager: Arc::clone(&group_manager),
        storage: Arc::clone(&storage),
        antispam: Arc::clone(&antispam),
        antivirus: Arc::clone(&antivirus),
        ldap_client: Arc::clone(&ldap_client),
        sso_manager: Arc::clone(&sso_manager),
        config: api_config,
        domain: domain.clone(),
        tokens: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
    };

    // Run servers
    tokio::select! {
        r = smtp_server.run(&smtp_addr) => {
            if let Err(e) = r { tracing::error!("SMTP error: {}", e); }
        }
        r = imap_server.run(&imap_addr) => {
            if let Err(e) = r { tracing::error!("IMAP error: {}", e); }
        }
        r = pop3_server.run(&pop3_addr) => {
            if let Err(e) = r { tracing::error!("POP3 error: {}", e); }
        }
        r = admin_api::run_api_server(api_state) => {
            if let Err(e) = r { tracing::error!("Admin API error: {}", e); }
        }
        r = admin_web::run_web_server(
            Arc::clone(&user_manager),
            Arc::clone(&group_manager),
            Arc::clone(&ldap_client),
            Arc::clone(&sso_manager),
            domain.clone(),
            web_config,
        ) => {
            if let Err(e) = r { tracing::error!("Web admin error: {}", e); }
        }
    }

    Ok(())
}

async fn handle_cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    // Parse global flags for remote mode
    let mut server: Option<String> = None;
    let mut api_key: Option<String> = None;
    let mut remaining_args: Vec<String> = Vec::new();
    let mut skip_next = false;

    for (i, arg) in args.iter().enumerate().skip(1) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--server" || arg == "-s" {
            server = args.get(i + 1).cloned();
            skip_next = true;
        } else if arg.starts_with("--server=") {
            server = Some(arg.trim_start_matches("--server=").to_string());
        } else if arg == "--api-key" || arg == "-k" {
            api_key = args.get(i + 1).cloned();
            skip_next = true;
        } else if arg.starts_with("--api-key=") {
            api_key = Some(arg.trim_start_matches("--api-key=").to_string());
        } else {
            remaining_args.push(arg.clone());
        }
    }

    // Also check env vars
    if server.is_none() {
        server = env::var("KISS_MAIL_SERVER").ok();
    }
    if api_key.is_none() {
        api_key = env::var("KISS_MAIL_API_KEY").ok();
    }

    let cmd = remaining_args.first().map(|s| s.as_str()).unwrap_or("");
    let cmd_args: Vec<String> = remaining_args.iter().skip(1).cloned().collect();

    // Remote mode
    if let Some(srv) = server {
        return handle_remote_cli(&srv, api_key, cmd, &cmd_args).await;
    }

    match cmd {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "version" | "--version" | "-v" => {
            println!("kiss-mail {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        // User management shortcuts
        "user" | "users" | "list" => run_admin("list", &cmd_args).await,
        "add" | "create" => run_admin("create", &cmd_args).await,
        "del" | "delete" | "rm" => run_admin("delete", &cmd_args).await,
        "passwd" | "password" => run_admin("passwd", &cmd_args).await,
        "info" => run_admin("info", &cmd_args).await,
        "stats" => run_admin("stats", &[]).await,
        "status" => run_admin("stats", &[]).await,
        // Group management
        "groups" | "group-list" => run_group_cmd("list", &cmd_args).await,
        "group-add" | "group-create" => run_group_cmd("create", &cmd_args).await,
        "group-del" | "group-delete" => run_group_cmd("delete", &cmd_args).await,
        "group-info" => run_group_cmd("info", &cmd_args).await,
        "group-members" => run_group_cmd("members", &cmd_args).await,
        "group-add-member" => run_group_cmd("add-member", &cmd_args).await,
        "group-rm-member" => run_group_cmd("rm-member", &cmd_args).await,
        // LDAP commands
        "ldap-test" => run_ldap_cmd("test", &cmd_args).await,
        "ldap-auth" => run_ldap_cmd("auth", &cmd_args).await,
        "ldap-search" => run_ldap_cmd("search", &cmd_args).await,
        // SSO commands
        "sso-status" => run_sso_cmd("status", &cmd_args).await,
        "app-password" | "app-pass" => run_sso_cmd("generate", &cmd_args).await,
        "app-passwords" | "app-pass-list" => run_sso_cmd("list", &cmd_args).await,
        "app-pass-revoke" => run_sso_cmd("revoke", &cmd_args).await,
        _ => {
            eprintln!("Unknown command: {}", cmd);
            eprintln!("Run 'kiss-mail help' for usage.");
            std::process::exit(1);
        }
    }
}

async fn handle_remote_cli(
    server: &str,
    api_key: Option<String>,
    cmd: &str,
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let client = if let Some(key) = api_key {
        RemoteClient::new(server).with_api_key(key)
    } else {
        // Prompt for credentials if no API key
        eprintln!("No API key provided. Use --api-key or set KISS_MAIL_API_KEY");
        eprintln!("You can also set KISS_MAIL_SERVER for the server address.");
        std::process::exit(1);
    };

    match cmd {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        "version" | "--version" | "-v" => {
            println!("kiss-mail {} (remote client)", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "status" | "stats" => {
            match client.status().await {
                Ok(status) => {
                    println!("Server Status:");
                    println!("  Version:     {}", status.version);
                    println!("  Domain:      {}", status.domain);
                    println!("  Users:       {}", status.users);
                    println!("  Groups:      {}", status.groups);
                    println!(
                        "  LDAP:        {}",
                        if status.ldap_enabled {
                            "Enabled"
                        } else {
                            "Disabled"
                        }
                    );
                    if let Some(provider) = status.sso_provider {
                        println!("  SSO:         {} enabled", provider);
                    } else {
                        println!(
                            "  SSO:         {}",
                            if status.sso_enabled {
                                "Enabled"
                            } else {
                                "Disabled"
                            }
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        // User commands
        "list" | "users" => {
            match client.list_users().await {
                Ok(users) => {
                    if users.is_empty() {
                        println!("No users found.");
                    } else {
                        println!("Users:");
                        for u in users {
                            println!("  {} ({}) - {}", u.username, u.role, u.status);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "add" | "create" => {
            if args.len() < 2 {
                eprintln!("Usage: kiss-mail --server <srv> add <user> <pass> [role]");
                std::process::exit(1);
            }
            let role = args.get(2).map(|s| s.as_str());
            match client.create_user(&args[0], &args[1], role).await {
                Ok(user) => {
                    println!("✓ Created user '{}'", user.username);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "del" | "delete" | "rm" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail --server <srv> del <user>");
                std::process::exit(1);
            }
            match client.delete_user(&args[0]).await {
                Ok(()) => {
                    println!("✓ Deleted user '{}'", args[0]);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "info" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail --server <srv> info <user>");
                std::process::exit(1);
            }
            match client.get_user(&args[0]).await {
                Ok(user) => {
                    println!("User: {}", user.username);
                    println!("  Role:         {}", user.role);
                    println!("  Status:       {}", user.status);
                    if let Some(name) = user.display_name {
                        println!("  Display name: {}", name);
                    }
                    println!("  Created:      {}", user.created_at);
                    if let Some(login) = user.last_login {
                        println!("  Last login:   {}", login);
                    }
                    println!("  Login count:  {}", user.login_count);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        // Group commands
        "groups" | "group-list" => {
            match client.list_groups().await {
                Ok(groups) => {
                    if groups.is_empty() {
                        println!("No groups found.");
                    } else {
                        println!("Groups:");
                        for g in groups {
                            println!("  {} ({}) - {} members", g.name, g.email, g.members.len());
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "group-add" | "group-create" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail --server <srv> group-add <name> [email]");
                std::process::exit(1);
            }
            let email = args.get(1).map(|s| s.as_str()).unwrap_or(&args[0]);
            match client.create_group(&args[0], email).await {
                Ok(group) => {
                    println!(
                        "✓ Created group '{}' with email '{}'",
                        group.name, group.email
                    );
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "group-del" | "group-delete" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail --server <srv> group-del <name>");
                std::process::exit(1);
            }
            match client.delete_group(&args[0]).await {
                Ok(()) => {
                    println!("✓ Deleted group '{}'", args[0]);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "group-add-member" => {
            if args.len() < 2 {
                eprintln!("Usage: kiss-mail --server <srv> group-add-member <group> <user>");
                std::process::exit(1);
            }
            match client.add_group_member(&args[0], &args[1]).await {
                Ok(()) => {
                    println!("✓ Added '{}' to group '{}'", args[1], args[0]);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "group-rm-member" => {
            if args.len() < 2 {
                eprintln!("Usage: kiss-mail --server <srv> group-rm-member <group> <user>");
                std::process::exit(1);
            }
            match client.remove_group_member(&args[0], &args[1]).await {
                Ok(()) => {
                    println!("✓ Removed '{}' from group '{}'", args[1], args[0]);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        "ldap-test" => {
            match client.ldap_test().await {
                Ok(msg) => {
                    println!("✓ LDAP: {}", msg);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
            Ok(())
        }
        _ => {
            eprintln!("Unknown command for remote mode: {}", cmd);
            eprintln!("Run 'kiss-mail help' for usage.");
            std::process::exit(1);
        }
    }
}

async fn run_admin(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = env::var("KISS_MAIL_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./mail_data"));

    // Ensure data directory exists
    let _ = tokio::fs::create_dir_all(&data_dir).await;

    let domain = env::var("KISS_MAIL_DOMAIN")
        .ok()
        .or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
        .unwrap_or_else(|| "localhost".to_string());

    let user_manager = Arc::new(UserManager::new(domain, data_dir.clone()));

    // Load existing data
    if let Err(e) = user_manager.load().await {
        eprintln!("Note: Could not load existing users: {}", e);
    }

    // Bootstrap admin if needed
    if !user_manager.user_exists("admin").await {
        match user_manager
            .create_user("admin", "changeme", Some(UserRole::SuperAdmin))
            .await
        {
            Ok(_) => { /* create_user already saves */ }
            Err(e) => eprintln!("Warning: Could not create admin: {}", e),
        }
    }

    let storage = Arc::new(Storage::new(data_dir.clone(), Arc::clone(&user_manager)));
    let _ = storage.load().await;

    let handler = AdminHandler::new(Arc::clone(&storage));
    let cmd_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = handler.execute(cmd, &cmd_args, "admin").await;

    println!("{}", format_result(&result));

    // Save all changes
    if let Err(e) = storage.save().await {
        eprintln!("Warning: Could not save storage: {}", e);
    }

    Ok(())
}

async fn run_group_cmd(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = env::var("KISS_MAIL_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./mail_data"));

    let _ = tokio::fs::create_dir_all(&data_dir).await;

    let domain = env::var("KISS_MAIL_DOMAIN")
        .ok()
        .or_else(|| hostname::get().ok().and_then(|h| h.into_string().ok()))
        .unwrap_or_else(|| "localhost".to_string());

    let group_manager = GroupManager::new(data_dir);
    if let Err(e) = group_manager.load().await {
        eprintln!("Note: Could not load existing groups: {}", e);
    }

    match cmd {
        "list" => {
            let groups = group_manager.list(Some("admin"), true).await;
            if groups.is_empty() {
                println!("No groups found.");
            } else {
                println!("Groups:");
                for g in groups {
                    println!("  {} ({}) - {} members", g.name, g.email, g.members.len());
                }
            }
        }
        "create" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail group-add <name> [email]");
                std::process::exit(1);
            }
            let name = &args[0];
            let email = args.get(1).map(|s| s.as_str()).unwrap_or_else(|| {
                // Default email based on name and domain
                ""
            });
            let email = if email.is_empty() {
                format!("{}@{}", name, domain)
            } else {
                email.to_string()
            };

            match group_manager.create(name, &email, "admin").await {
                Ok(g) => println!("Created group '{}' with email '{}'", g.name, g.email),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        "delete" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail group-del <name>");
                std::process::exit(1);
            }
            match group_manager.delete(&args[0], "admin").await {
                Ok(()) => println!("Deleted group '{}'", args[0]),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        "info" | "members" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail group-info <name>");
                std::process::exit(1);
            }
            match group_manager.get(&args[0]).await {
                Some(g) => {
                    println!("Group: {}", g.name);
                    println!("  Email:       {}", g.email);
                    println!("  Display:     {}", g.display_name);
                    println!("  Owner:       {}", g.owner);
                    println!("  Visibility:  {:?}", g.visibility);
                    println!("  Active:      {}", g.active);
                    println!("  Members ({}):", g.members.len());
                    for m in &g.members {
                        let role = if g.is_owner(m) {
                            " (owner)"
                        } else if g.is_manager(m) {
                            " (manager)"
                        } else {
                            ""
                        };
                        println!("    - {}{}", m, role);
                    }
                }
                None => eprintln!("Group '{}' not found", args[0]),
            }
        }
        "add-member" => {
            if args.len() < 2 {
                eprintln!("Usage: kiss-mail group-add-member <group> <user>");
                std::process::exit(1);
            }
            match group_manager.add_member(&args[0], &args[1], "admin").await {
                Ok(()) => println!("Added '{}' to group '{}'", args[1], args[0]),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        "rm-member" => {
            if args.len() < 2 {
                eprintln!("Usage: kiss-mail group-rm-member <group> <user>");
                std::process::exit(1);
            }
            match group_manager
                .remove_member(&args[0], &args[1], "admin")
                .await
            {
                Ok(()) => println!("Removed '{}' from group '{}'", args[1], args[0]),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        _ => {
            eprintln!("Unknown group command: {}", cmd);
        }
    }

    Ok(())
}

async fn run_ldap_cmd(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let ldap_client = LdapClient::from_env();

    if !ldap_client.is_enabled() {
        println!("LDAP is not configured.");
        println!();
        println!("To enable LDAP, set these environment variables:");
        println!("  LDAP_URL=ldap://your-ldap-server:389");
        println!("  LDAP_BASE_DN=dc=example,dc=com");
        println!("  LDAP_BIND_DN=cn=admin,dc=example,dc=com  (optional)");
        println!("  LDAP_BIND_PASSWORD=secret                (optional)");
        println!();
        println!("See 'kiss-mail help' for all LDAP options.");
        return Ok(());
    }

    match cmd {
        "test" => {
            println!("Testing LDAP connection...");
            let status = ldap_client.status();
            println!("  URL:      {}", status.url);
            println!("  Base DN:  {}", status.base_dn);
            println!(
                "  TLS:      {}",
                if status.use_tls {
                    "Yes"
                } else if status.use_starttls {
                    "StartTLS"
                } else {
                    "No"
                }
            );
            println!();

            match ldap_client.test_connection().await {
                Ok(msg) => {
                    println!("✓ {}", msg);
                }
                Err(e) => {
                    eprintln!("✗ Connection failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "auth" => {
            if args.len() < 2 {
                eprintln!("Usage: kiss-mail ldap-auth <username> <password>");
                std::process::exit(1);
            }
            let username = &args[0];
            let password = &args[1];

            println!("Authenticating {} via LDAP...", username);
            match ldap_client.authenticate(username, password).await {
                ldap::LdapAuthResult::Success(user) => {
                    println!("✓ Authentication successful!");
                    println!("  DN:      {}", user.dn);
                    println!("  Email:   {}", user.email.as_deref().unwrap_or("(none)"));
                    println!(
                        "  Name:    {}",
                        user.display_name.as_deref().unwrap_or("(none)")
                    );
                    if !user.groups.is_empty() {
                        println!("  Groups:  {}", user.groups.len());
                        for g in user.groups.iter().take(5) {
                            println!("    - {}", g);
                        }
                        if user.groups.len() > 5 {
                            println!("    ... and {} more", user.groups.len() - 5);
                        }
                    }
                }
                ldap::LdapAuthResult::InvalidCredentials => {
                    eprintln!("✗ Invalid credentials");
                    std::process::exit(1);
                }
                ldap::LdapAuthResult::UserNotFound => {
                    eprintln!("✗ User not found in LDAP");
                    std::process::exit(1);
                }
                ldap::LdapAuthResult::Error(e) => {
                    eprintln!("✗ LDAP error: {}", e);
                    std::process::exit(1);
                }
                ldap::LdapAuthResult::NotEnabled => {
                    eprintln!("LDAP is not enabled");
                    std::process::exit(1);
                }
            }
        }
        "search" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail ldap-search <username>");
                std::process::exit(1);
            }
            let username = &args[0];

            println!("Searching for {} in LDAP...", username);
            match ldap_client.get_user(username).await {
                Ok(Some(user)) => {
                    println!("✓ Found user:");
                    println!("  DN:       {}", user.dn);
                    println!("  Username: {}", user.username);
                    println!("  Email:    {}", user.email.as_deref().unwrap_or("(none)"));
                    println!(
                        "  Name:     {}",
                        user.display_name.as_deref().unwrap_or("(none)")
                    );
                }
                Ok(None) => {
                    println!("User '{}' not found in LDAP", username);
                }
                Err(e) => {
                    eprintln!("✗ Search failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            eprintln!("Unknown LDAP command: {}", cmd);
        }
    }

    Ok(())
}

async fn run_sso_cmd(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = env::var("KISS_MAIL_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./mail_data"));

    let _ = tokio::fs::create_dir_all(&data_dir).await;

    let sso_manager = SsoManager::from_env(data_dir);
    let _ = sso_manager.load().await;

    match cmd {
        "status" => {
            let status = sso_manager.status();
            println!("SSO Status:");
            println!(
                "  Enabled:        {}",
                if status.enabled { "Yes" } else { "No" }
            );
            if status.enabled {
                println!("  Provider:       {}", status.provider_name);
                println!(
                    "  App Passwords:  {}",
                    if status.allow_app_passwords {
                        "Allowed"
                    } else {
                        "Disabled"
                    }
                );
            } else {
                println!();
                println!("To enable SSO, set provider environment variables:");
                println!();
                println!("  1Password:");
                println!("     ONEPASSWORD_CLIENT_ID=<client_id>");
                println!("     ONEPASSWORD_CLIENT_SECRET=<secret>");
                println!();
                println!("  Google:");
                println!("     GOOGLE_CLIENT_ID=<client_id>");
                println!("     GOOGLE_CLIENT_SECRET=<secret>");
                println!();
                println!("  Microsoft:");
                println!("     MICROSOFT_CLIENT_ID=<client_id>");
                println!("     MICROSOFT_CLIENT_SECRET=<secret>");
                println!("     MICROSOFT_TENANT_ID=<tenant_id>");
                println!();
                println!("  Generic OIDC:");
                println!("     SSO_CLIENT_ID=<client_id>");
                println!("     SSO_CLIENT_SECRET=<secret>");
                println!("     SSO_AUTH_URL=<auth_endpoint>");
                println!("     SSO_TOKEN_URL=<token_endpoint>");
            }
        }
        "generate" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail app-password <username> [label]");
                std::process::exit(1);
            }
            let username = &args[0];
            let label = args.get(1).map(|s| s.as_str()).unwrap_or("Mail Client");

            match sso_manager
                .generate_app_password(username, label, None)
                .await
            {
                Ok(password) => {
                    println!("✓ Generated app password for '{}'", username);
                    println!();
                    println!("  Label:    {}", label);
                    println!("  Password: {}", password);
                    println!();
                    println!(
                        "  Use this password in your email client instead of your SSO password."
                    );
                    println!("  Store it securely - it won't be shown again!");
                }
                Err(e) => {
                    eprintln!("✗ Failed to generate app password: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "list" => {
            if args.is_empty() {
                eprintln!("Usage: kiss-mail app-passwords <username>");
                std::process::exit(1);
            }
            let username = &args[0];
            let passwords = sso_manager.list_app_passwords(username).await;

            if passwords.is_empty() {
                println!("No app passwords for '{}'", username);
            } else {
                println!("App passwords for '{}':", username);
                for pw in passwords {
                    let status = if let Some(expires) = pw.expires_at {
                        if chrono::Utc::now() > expires {
                            " (EXPIRED)"
                        } else {
                            ""
                        }
                    } else {
                        ""
                    };
                    let last_used = pw
                        .last_used
                        .map(|d| d.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "Never".to_string());
                    println!("  {} - {}{}", &pw.id[..8], pw.label, status);
                    println!("    Created:   {}", pw.created_at.format("%Y-%m-%d %H:%M"));
                    println!("    Last used: {}", last_used);
                }
            }
        }
        "revoke" => {
            if args.len() < 2 {
                eprintln!("Usage: kiss-mail app-pass-revoke <username> <password_id>");
                std::process::exit(1);
            }
            let username = &args[0];
            let password_id = &args[1];

            if sso_manager.revoke_app_password(username, password_id).await {
                println!("✓ Revoked app password");
            } else {
                eprintln!("✗ App password not found");
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("Unknown SSO command: {}", cmd);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn print_banner(
    domain: &str,
    smtp: u16,
    imap: u16,
    pop3: u16,
    api_port: u16,
    api_enabled: bool,
    web_port: u16,
    web_enabled: bool,
    um: &UserManager,
    gm: &GroupManager,
    ldap: &LdapClient,
    sso: &SsoManager,
    antispam: &AntiSpam,
    av: &AntiVirus,
    crypto: &crypto::CryptoManager,
) {
    let stats = um.get_stats().await;
    let group_stats = gm.get_stats().await;
    let ldap_status = ldap.status();
    let sso_status = sso.status();
    let av_status = av.status();
    let ai_stats = antispam.ai_stats().await;
    let crypto_status = crypto.status();
    let crypto_stats = crypto.stats().await;

    println!();
    println!("  ╦╔═╦╔══╗  ╔╦╗╔═╗╦╦  ");
    println!("  ╠╩╗║╚═╗╚═╗║║║╠═╣║║  ");
    println!("  ╩ ╩╩╚═╝╚═╝╩ ╩╩ ╩╩╩═╝");
    println!("  Simple Email Server {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  📧 Domain:  {}", domain);
    println!("  👥 Users:   {}", stats.total_users);
    println!("  📋 Groups:  {}", group_stats.total_groups);
    println!();
    println!("  Servers:");
    println!("    SMTP  →  localhost:{}", smtp);
    println!("    IMAP  →  localhost:{}", imap);
    println!("    POP3  →  localhost:{}", pop3);
    if api_enabled {
        println!("    API   →  localhost:{}", api_port);
    }
    if web_enabled {
        println!("    Web   →  http://localhost:{}/admin", web_port);
    }
    println!();
    println!("  Security:");
    println!(
        "    Anti-spam   ✓ Rules + AI ({} patterns learned)",
        ai_stats.total_tokens
    );
    if av_status.clamav_available {
        println!(
            "    Anti-virus  ✓ ClamAV {}",
            av_status.clamav_version.as_deref().unwrap_or("")
        );
    } else if av_status.clamav_enabled {
        println!("    Anti-virus  ✓ Built-in (ClamAV not found)");
    } else {
        println!("    Anti-virus  ✓ Built-in");
    }
    if crypto_status.enabled {
        println!(
            "    Encryption  ✓ {} ({} keys)",
            crypto_status.algorithm, crypto_stats.total_keys
        );
    } else {
        println!("    Encryption  ✗ Disabled (set KISS_MAIL_ENCRYPTION=true)");
    }
    println!();
    println!("  Identity:");
    if ldap_status.enabled {
        let tls = if ldap_status.use_tls {
            " (TLS)"
        } else if ldap_status.use_starttls {
            " (StartTLS)"
        } else {
            ""
        };
        println!("    LDAP        ✓ {}{}", ldap_status.url, tls);
    } else {
        println!("    LDAP        ✗ Not configured");
    }
    if sso_status.enabled {
        let app_pw = if sso_status.allow_app_passwords {
            " + app passwords"
        } else {
            ""
        };
        println!("    SSO         ✓ {}{}", sso_status.provider_name, app_pw);
    } else {
        println!("    SSO         ✗ Not configured");
    }
    println!();
    if api_enabled {
        println!("  Remote CLI:");
        println!(
            "    kiss-mail --server localhost:{} --api-key <key> <cmd>",
            api_port
        );
        println!();
    }
    println!("  Quick commands:");
    println!("    kiss-mail add <user> <pass>   Create user");
    println!("    kiss-mail list                List users");
    println!("    kiss-mail group-add <name>    Create group");
    println!("    kiss-mail stats               Show stats");
    println!();
    println!("  Press Ctrl+C to stop");
    println!();
}

fn print_help() {
    println!(
        r#"
KISS Mail - Simple Email Server

USAGE:
    kiss-mail                            Start the mail server
    kiss-mail <command>                  Run a command locally
    kiss-mail --server <url> <command>   Run a command on remote server

REMOTE CLI:
    --server, -s <url>    Connect to remote server (or KISS_MAIL_SERVER)
    --api-key, -k <key>   API key for authentication (or KISS_MAIL_API_KEY)

USER COMMANDS:
    add <user> <pass>      Create a new user
    del <user>             Delete a user  
    list                   List all users
    info <user>            Show user details
    passwd <user> <pass>   Change password
    stats / status         Show server stats

GROUP COMMANDS:
    groups                        List all groups
    group-add <name> [email]      Create a new group
    group-del <name>              Delete a group
    group-info <name>             Show group details
    group-add-member <grp> <usr>  Add user to group
    group-rm-member <grp> <usr>   Remove user from group

LDAP COMMANDS:
    ldap-test                     Test LDAP connection
    ldap-auth <user> <pass>       Test LDAP authentication
    ldap-search <user>            Search for user in LDAP

SSO COMMANDS:
    sso-status                    Show SSO configuration
    app-password <user> [label]   Generate app password
    app-passwords <user>          List app passwords
    app-pass-revoke <user> <id>   Revoke app password

GENERAL:
    help                   Show this help
    version                Show version

ENVIRONMENT:
    KISS_MAIL_DATA      Data directory (default: ./mail_data)
    KISS_MAIL_DOMAIN    Email domain (default: hostname)
    SMTP_PORT           SMTP port (default: 2525 or 25 if root)
    IMAP_PORT           IMAP port (default: 1143 or 143 if root)
    POP3_PORT           POP3 port (default: 1100 or 110 if root)

ADMIN API CONFIGURATION:
    KISS_MAIL_API_KEY     API key for remote access (enables API)
    KISS_MAIL_API_PORT    Admin API port (default: 8025)
    KISS_MAIL_API_BIND    Admin API bind address (default: 127.0.0.1)
    KISS_MAIL_API_ENABLED Set to 'true' to enable without API key

LDAP CONFIGURATION:
    LDAP_URL              LDAP server URL (e.g., ldap://localhost:389)
    LDAP_BASE_DN          Base DN for searches (e.g., dc=example,dc=com)
    LDAP_BIND_DN          Service account DN (optional)
    LDAP_BIND_PASSWORD    Service account password (optional)
    LDAP_USER_FILTER      User search filter (default: uid={{username}})
    LDAP_USER_DN_TEMPLATE DN template (e.g., uid={{username}},ou=users,dc=example,dc=com)
    LDAP_USE_TLS          Enable TLS (1/true)
    LDAP_FALLBACK_LOCAL   Fall back to local auth if LDAP fails (default: true)

SSO CONFIGURATION (pick one provider):
    1Password:
      ONEPASSWORD_CLIENT_ID      OAuth2 client ID
      ONEPASSWORD_CLIENT_SECRET  OAuth2 client secret
    Google:
      GOOGLE_CLIENT_ID           OAuth2 client ID
      GOOGLE_CLIENT_SECRET       OAuth2 client secret
    Microsoft:
      MICROSOFT_CLIENT_ID        OAuth2 client ID
      MICROSOFT_CLIENT_SECRET    OAuth2 client secret
      MICROSOFT_TENANT_ID        Azure AD tenant ID
    Okta:
      OKTA_CLIENT_ID             OAuth2 client ID
      OKTA_CLIENT_SECRET         OAuth2 client secret
      OKTA_DOMAIN                Okta domain (e.g., dev-123456.okta.com)
    Generic OIDC:
      SSO_CLIENT_ID              OAuth2 client ID
      SSO_CLIENT_SECRET          OAuth2 client secret
      SSO_AUTH_URL               Authorization endpoint
      SSO_TOKEN_URL              Token endpoint
      SSO_USERINFO_URL           UserInfo endpoint

EXAMPLES:
    # Local commands
    kiss-mail                               # Start server
    kiss-mail add alice secret123           # Create user
    kiss-mail group-add developers          # Create group
    kiss-mail ldap-test                     # Test LDAP connection

    # Remote commands
    kiss-mail -s mail.example.com:8025 -k myapikey list
    kiss-mail --server=localhost:8025 --api-key=secret status
    
    # Using environment variables
    export KISS_MAIL_SERVER=mail.example.com:8025
    export KISS_MAIL_API_KEY=myapikey
    kiss-mail list
    kiss-mail add bob secret456

REMOTE ADMINISTRATION:
    To enable the admin API on the server:
    
      export KISS_MAIL_API_KEY=your-secret-key
      kiss-mail
    
    Then from any machine with the CLI:
    
      kiss-mail --server mail.example.com:8025 --api-key your-secret-key list
    
    The API provides REST endpoints at /api/* for programmatic access:
      POST /api/auth/login      Login with admin credentials
      GET  /api/status          Server status
      GET  /api/users           List users
      POST /api/users           Create user
      GET  /api/groups          List groups
      POST /api/groups          Create group
      ...and more

CONNECTING:
    Configure your email client with:
      Server:   localhost (or your server's address)
      SMTP:     Port {smtp} 
      IMAP:     Port {imap}
      POP3:     Port {pop3}
      Username: your_username
      Password: your_password
      Security: None (or STARTTLS if configured)
"#,
        smtp = 2525,
        imap = 1143,
        pop3 = 1100
    );
}

fn generate_simple_password() -> String {
    use rand::Rng;
    let words = [
        "apple", "banana", "cherry", "dragon", "eagle", "forest", "guitar", "hammer", "island",
        "jungle", "knight", "lemon", "mango", "north", "ocean", "piano", "queen", "river",
        "silver", "tiger", "umbrella", "violet", "winter", "yellow",
    ];
    let mut rng = rand::rng();
    let w1 = words[rng.random_range(0..words.len())];
    let w2 = words[rng.random_range(0..words.len())];
    let num: u16 = rng.random_range(10..99);
    format!("{}-{}-{}", w1, w2, num)
}
