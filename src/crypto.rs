use anyhow::{Context, Result};
use colored::*;
use dood_encryption::x3dh::X3DH;
use std::fs;
use std::path::Path;

use crate::{auth, database};

pub fn export_keys(output_path: &str) -> Result<()> {
    let username = auth::get_current_username()?;
    let conn = database::get_connection()?;

    // Get key bundle
    let key_bundle: String = conn.query_row(
        "SELECT key_bundle FROM account WHERE username = ?1",
        rusqlite::params![username],
        |row| row.get(0),
    )?;

    // Create export data
    let export_data = serde_json::json!({
        "username": username,
        "key_bundle": key_bundle,
        "version": "1.0",
        "exported_at": chrono::Utc::now().to_rfc3339(),
    });

    // Write to file
    let json_str = serde_json::to_string_pretty(&export_data)?;
    fs::write(output_path, json_str)?;

    println!(
        "{} Keys exported to {}",
        "✓".green().bold(),
        output_path.bold()
    );
    println!(
        "{}",
        "⚠️  Keep this file secure! Anyone with access can read your messages.".yellow()
    );

    Ok(())
}

pub fn import_keys(input_path: &str) -> Result<()> {
    if !Path::new(input_path).exists() {
        anyhow::bail!("File not found: {}", input_path);
    }

    // Read file
    let json_str = fs::read_to_string(input_path)?;
    let import_data: serde_json::Value = serde_json::from_str(&json_str)?;

    let username = import_data["username"]
        .as_str()
        .context("Invalid export file: missing username")?;
    let key_bundle_str = import_data["key_bundle"]
        .as_str()
        .context("Invalid export file: missing key_bundle")?;

    // Check if account already exists
    let conn = database::get_connection()?;
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM account WHERE username = ?1",
        rusqlite::params![username],
        |row| row.get::<_, i32>(0).map(|count| count > 0),
    )?;

    if exists {
        anyhow::bail!(
            "Account '{}' already exists. Please delete it first.",
            username
        );
    }

    // Parse and validate the key bundle
    let key_bundle_json: serde_json::Value = serde_json::from_str(key_bundle_str)?;
    let x3dh = X3DH::from(key_bundle_json);

    // Save to database
    let now = chrono::Utc::now().to_rfc3339();
    let identity_pub = auth::get_identity_public_key(&x3dh);
    let identity_pub_bytes = identity_pub.to_bytes();

    conn.execute(
        "INSERT INTO account (username, identity_private_key, identity_public_key, 
                              signed_pre_key_private, signed_pre_key_public, 
                              signed_pre_key_signature, key_bundle, server_url, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            username,
            &[] as &[u8],
            &identity_pub_bytes[..],
            &[] as &[u8],
            &[] as &[u8],
            &[] as &[u8],
            key_bundle_str,
            "http://localhost:8080", // Default server
            now,
        ],
    )?;

    println!(
        "{} Account '{}' imported successfully!",
        "✓".green().bold(),
        username.bold()
    );
    println!("{}", "You can now login with this account.".green());

    Ok(())
}
