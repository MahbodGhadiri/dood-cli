use anyhow::Result;
use base64::{prelude::BASE64_STANDARD, Engine};
use chrono::{DateTime, Local, Utc};
use colored::*;
use std::io::{self, Write};

use crate::{auth, database, messages};

pub fn display_chats() -> Result<()> {
    let conversations = database::get_conversations()?;

    if conversations.is_empty() {
        println!("{}", "No conversations yet.".yellow());
        return Ok(());
    }

    println!("\n{}", "📱 Your Conversations".bold().cyan());
    println!("{}", "─".repeat(60).bright_black());

    for (username, last_time, last_msg, unread) in conversations {
        let time_str = format_timestamp(&last_time);
        let preview = truncate(&last_msg, 40);

        let unread_badge = if unread > 0 {
            format!(" {}", format!("[{}]", unread).bright_red().bold())
        } else {
            String::new()
        };

        println!(
            "{} {} {}{}",
            "👤".bold(),
            username.bold().green(),
            time_str.bright_black(),
            unread_badge
        );
        println!("   {}", preview.bright_black());
        println!();
    }

    Ok(())
}

pub fn display_history(username: &str, limit: usize) -> Result<()> {
    let messages = database::get_messages(username, limit)?;

    if messages.is_empty() {
        println!("{}", format!("No messages with {}", username).yellow());
        return Ok(());
    }

    println!(
        "\n{} {}",
        "💬 Conversation with".bold().cyan(),
        username.bold()
    );
    println!("{}", "─".repeat(60).bright_black());
    println!();

    for msg in messages.iter().rev() {
        let time_str = format_timestamp(&msg.timestamp);

        if msg.is_outgoing {
            println!(
                "{} {} {}",
                "You".bold().blue(),
                "→".bright_black(),
                time_str.bright_black()
            );
            println!("  {}", msg.content.white());
        } else {
            println!(
                "{} {} {}",
                username.bold().green(),
                "→".bright_black(),
                time_str.bright_black()
            );
            println!("  {}", msg.content.white());
        }
        println!();
    }

    database::mark_messages_as_read(username)?;

    Ok(())
}

pub async fn interactive_chat(username: &str) -> Result<()> {
    println!("\n{} {}", "💬 Chat with".bold().cyan(), username.bold());
    println!("{}", "─".repeat(60).bright_black());
    println!(
        "{}",
        "Type your message and press Enter. Type '/quit' to exit.".bright_black()
    );
    println!();

    let messages = database::get_messages(username, 10)?;
    for msg in messages.iter().rev() {
        if msg.is_outgoing {
            println!("{} {}", "You:".bold().blue(), msg.content);
        } else {
            println!(
                "{} {}",
                format!("{}:", username).bold().green(),
                msg.content
            );
        }
    }

    if !messages.is_empty() {
        println!("{}", "─".repeat(60).bright_black());
    }

    database::mark_messages_as_read(username)?;

    loop {
        print!("{} ", ">".bright_blue().bold());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        if input == "/quit" || input == "/exit" {
            break;
        }

        if input == "/fetch" {
            if let Err(e) = messages::fetch_messages().await {
                eprintln!("{} {}", "Error:".red(), e);
            }
            continue;
        }

        match messages::send_message(username, input).await {
            Ok(_) => {
                println!("{}", "  ✓ Sent".green());
            }
            Err(e) => {
                eprintln!("{} {}", "  ✗ Error:".red(), e);
            }
        }
    }

    println!("{}", "\nChat ended.".bright_black());

    Ok(())
}

pub fn display_account_info() -> Result<()> {
    let username = auth::get_current_username()?;
    let x3dh = auth::get_current_x3dh()?;
    let server_url = auth::get_server_url()?;

    let identity_pub = auth::get_identity_public_key(&x3dh);
    let identity_pub_b64 = BASE64_STANDARD.encode(identity_pub.to_bytes());

    println!("\n{}", "👤 Account Information".bold().cyan());
    println!("{}", "─".repeat(60).bright_black());
    println!("{} {}", "Username:".bold(), username.green());
    println!("{} {}", "Server:".bold(), server_url);
    println!(
        "{} {}",
        "Identity Key:".bold(),
        truncate(&identity_pub_b64, 50).bright_black()
    );
    println!();

    let conversations = database::get_conversations()?;
    println!("{} {}", "Conversations:".bold(), conversations.len());

    let conn = database::get_connection()?;
    let total_messages: i32 =
        conn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))?;
    println!("{} {}", "Total Messages:".bold(), total_messages);

    Ok(())
}

fn format_timestamp(dt: &DateTime<Utc>) -> String {
    let local: DateTime<Local> = dt.with_timezone(&Local::now().timezone());
    let now = Local::now();

    if local.date_naive() == now.date_naive() {
        local.format("%H:%M").to_string()
    } else if (now - local).num_days() < 7 {
        local.format("%a %H:%M").to_string()
    } else {
        local.format("%b %d").to_string()
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}
