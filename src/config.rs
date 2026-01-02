use anyhow::Result;
use colored::*;
use rusqlite::params;

use crate::database;

pub fn set_server_url(new_url: &str) -> Result<()> {
    if !new_url.starts_with("http://") && !new_url.starts_with("https://") {
        anyhow::bail!("Invalid URL format. Must start with http:// or https://");
    }

    let url = new_url.trim_end_matches('/');

    let conn = database::get_connection()?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES ('server_url', ?1)",
        params![url],
    )?;

    println!("{} Server URL set to: {}", "✓".green().bold(), url.bold());
    println!("{}", "You can now register or login.".bright_black());

    Ok(())
}

pub fn get_server_url() -> Result<String> {
    let conn = database::get_connection()?;

    let url: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT value FROM config WHERE key = 'server_url'",
        [],
        |row| row.get(0),
    );

    match url {
        Ok(url) => Ok(url),
        Err(_) => {
            anyhow::bail!(
                "Server URL not configured. Please run 'dood set-server --url <SERVER_URL>' first."
            )
        }
    }
}

pub fn is_server_configured() -> Result<bool> {
    let conn = database::get_connection()?;

    let table_exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='config'",
        [],
        |row| row.get::<_, i32>(0).map(|count| count > 0),
    )?;

    if !table_exists {
        return Ok(false);
    }

    let url_exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM config WHERE key = 'server_url'",
        [],
        |row| row.get::<_, i32>(0).map(|count| count > 0),
    )?;

    Ok(url_exists)
}
