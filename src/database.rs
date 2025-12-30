use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::PathBuf;

pub fn get_db_path() -> PathBuf {
    let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push(".dood");
    std::fs::create_dir_all(&path).ok();
    path.push("dood.db");
    path
}

pub fn get_connection() -> Result<Connection> {
    let conn = Connection::open(get_db_path())?;
    Ok(conn)
}

pub fn init() -> Result<()> {
    let conn = get_connection()?;

    // Account table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS account (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            identity_private_key BLOB NOT NULL,
            identity_public_key BLOB NOT NULL,
            signed_pre_key_private BLOB NOT NULL,
            signed_pre_key_public BLOB NOT NULL,
            signed_pre_key_signature BLOB NOT NULL,
            key_bundle TEXT NOT NULL,
            server_url TEXT NOT NULL,
            device_id INTEGER,
            created_at TEXT NOT NULL,
            last_login TEXT
        )",
        [],
    )?;

    // Messages table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_with TEXT NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            is_outgoing INTEGER NOT NULL,
            is_read INTEGER NOT NULL DEFAULT 0,
            message_id TEXT
        )",
        [],
    )?;

    // Ratchet states table (for ongoing conversations) - Changed to TEXT
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ratchet_states (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            state_data TEXT NOT NULL,
            last_updated TEXT NOT NULL
        )",
        [],
    )?;

    // Session table (current logged in user)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS session (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            username TEXT NOT NULL,
            logged_in_at TEXT NOT NULL
        )",
        [],
    )?;

    // Contacts/Key bundles cache
    conn.execute(
        "CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            identity_key BLOB NOT NULL,
            key_bundle TEXT,
            last_fetched TEXT NOT NULL
        )",
        [],
    )?;

    Ok(())
}

pub struct Message {
    pub id: i64,
    pub conversation_with: String,
    pub sender: String,
    pub recipient: String,
    pub content: String,
    pub timestamp: DateTime<Utc>,
    pub is_outgoing: bool,
    pub is_read: bool,
}

pub fn save_message(
    conversation_with: &str,
    sender: &str,
    recipient: &str,
    content: &str,
    is_outgoing: bool,
) -> Result<()> {
    let conn = get_connection()?;
    let timestamp = Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO messages (conversation_with, sender, recipient, content, timestamp, is_outgoing, is_read)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![conversation_with, sender, recipient, content, timestamp, is_outgoing as i32, 0],
    )?;

    Ok(())
}

pub fn get_messages(username: &str, limit: usize) -> Result<Vec<Message>> {
    let conn = get_connection()?;
    let mut stmt = conn.prepare(
        "SELECT id, conversation_with, sender, recipient, content, timestamp, is_outgoing, is_read
         FROM messages
         WHERE conversation_with = ?1
         ORDER BY timestamp DESC
         LIMIT ?2",
    )?;

    let messages = stmt
        .query_map(params![username, limit], |row| {
            Ok(Message {
                id: row.get(0)?,
                conversation_with: row.get(1)?,
                sender: row.get(2)?,
                recipient: row.get(3)?,
                content: row.get(4)?,
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(5)?)
                    .unwrap()
                    .with_timezone(&Utc),
                is_outgoing: row.get::<_, i32>(6)? != 0,
                is_read: row.get::<_, i32>(7)? != 0,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(messages)
}

pub fn get_conversations() -> Result<Vec<(String, DateTime<Utc>, String, i32)>> {
    let conn = get_connection()?;
    let mut stmt = conn.prepare(
        "SELECT conversation_with, MAX(timestamp) as last_message_time, 
                (SELECT content FROM messages m2 
                 WHERE m2.conversation_with = m1.conversation_with 
                 ORDER BY timestamp DESC LIMIT 1) as last_message,
                SUM(CASE WHEN is_read = 0 AND is_outgoing = 0 THEN 1 ELSE 0 END) as unread_count
         FROM messages m1
         GROUP BY conversation_with
         ORDER BY last_message_time DESC",
    )?;

    let conversations = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .unwrap()
                    .with_timezone(&Utc),
                row.get::<_, String>(2)?,
                row.get::<_, i32>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(conversations)
}

pub fn mark_messages_as_read(username: &str) -> Result<()> {
    let conn = get_connection()?;
    conn.execute(
        "UPDATE messages SET is_read = 1 WHERE conversation_with = ?1 AND is_outgoing = 0",
        params![username],
    )?;
    Ok(())
}
