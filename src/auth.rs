use anyhow::{Result, Context};
use base64::{prelude::BASE64_STANDARD, Engine};
use colored::*;
use rusqlite::params;
use serde_json::json;
use dood_encryption::x3dh::X3DH;
use x25519_dalek::PublicKey;

use crate::database;

pub async fn register(username: &str, server_url: Option<&str>) -> Result<()> {
    let server = server_url.unwrap_or("http://localhost:8080");
    
    println!("{}", "🔐 Generating cryptographic keys...".cyan());
    
    // Create new X3DH instance
    let x3dh = X3DH::new();
    
    // Export PUBLIC key bundle for server
    let public_key_bundle = x3dh.export();
    
    // Export PRIVATE keys for local storage
    let private_key_bundle = x3dh.export_private();
    
    println!("{}", "📡 Registering with server...".cyan());
    
    // Register with server (send PUBLIC keys only)
    let client = reqwest::Client::new();
    let payload = json!({
        "bundle": public_key_bundle,
        "username": username
    });
    
    let response = client
        .post(format!("{}/account/register", server))
        .json(&payload)
        .send()
        .await
        .context("Failed to connect to server")?;
    
    if !response.status().is_success() {
        let error_text = response.text().await?;
        anyhow::bail!("Registration failed: {}", error_text);
    }
    
    let response_text = response.text().await?;
    println!("{} {}", "✓".green(), response_text);
    
    // Save account to database (store PRIVATE keys)
    save_account(username, &x3dh, private_key_bundle.to_string(), server)?;
    
    // Set as current session
    set_session(username)?;
    
    println!("{} Account '{}' created successfully!", "✓".green().bold(), username.bold());
    println!("{}", "You are now logged in.".green());
    
    Ok(())
}

pub fn login(username: &str) -> Result<()> {
    let conn = database::get_connection()?;
    
    // Check if account exists
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM account WHERE username = ?1",
            params![username],
            |row| row.get::<_, i32>(0).map(|count| count > 0),
        )?;
    
    if !exists {
        anyhow::bail!("Account '{}' not found. Please register first.", username);
    }
    
    // Set session
    set_session(username)?;
    
    println!("{} Logged in as '{}'", "✓".green().bold(), username.bold());
    
    Ok(())
}

pub fn logout() -> Result<()> {
    let conn = database::get_connection()?;
    conn.execute("DELETE FROM session WHERE id = 1", [])?;
    println!("{} Logged out successfully", "✓".green().bold());
    Ok(())
}

pub fn is_logged_in() -> Result<bool> {
    let conn = database::get_connection()?;
    let count: i32 = conn.query_row(
        "SELECT COUNT(*) FROM session WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

pub fn get_current_username() -> Result<String> {
    let conn = database::get_connection()?;
    let username: String = conn.query_row(
        "SELECT username FROM session WHERE id = 1",
        [],
        |row| row.get(0),
    )?;
    Ok(username)
}

pub fn get_current_x3dh() -> Result<X3DH> {
    let username = get_current_username()?;
    load_x3dh(&username)
}

pub fn load_x3dh(username: &str) -> Result<X3DH> {
    let conn = database::get_connection()?;
    
    let key_bundle_str: String = conn.query_row(
        "SELECT key_bundle FROM account WHERE username = ?1",
        params![username],
        |row| row.get(0),
    )?;
    
    // Parse JSON and reconstruct X3DH from PRIVATE keys
    let key_bundle: serde_json::Value = serde_json::from_str(&key_bundle_str)?;
    let x3dh = X3DH::from_private(key_bundle);
    
    Ok(x3dh)
}

pub fn get_identity_public_key(x3dh: &X3DH) -> PublicKey {
    // Get the public key from the PUBLIC export (for server communication)
    let bundle = x3dh.export();
    let identity_key_b64 = bundle["identity_key"].as_str().unwrap();
    let identity_key_bytes = BASE64_STANDARD.decode(identity_key_b64).unwrap();
    let identity_key_array: [u8; 32] = identity_key_bytes.try_into().unwrap();
    PublicKey::from(identity_key_array)
}

fn save_account(username: &str, x3dh: &X3DH, private_key_bundle: String, server_url: &str) -> Result<()> {
    let conn = database::get_connection()?;
    let now = chrono::Utc::now().to_rfc3339();
    
    let identity_pub = get_identity_public_key(x3dh);
    let identity_pub_bytes = identity_pub.to_bytes();
    
    conn.execute(
        "INSERT INTO account (username, identity_private_key, identity_public_key, 
                              signed_pre_key_private, signed_pre_key_public, 
                              signed_pre_key_signature, key_bundle, server_url, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            username,
            &[] as &[u8], // We store everything in key_bundle
            &identity_pub_bytes[..],
            &[] as &[u8],
            &[] as &[u8],
            &[] as &[u8],
            private_key_bundle, // Store PRIVATE keys
            server_url,
            now,
        ],
    )?;
    
    Ok(())
}

fn set_session(username: &str) -> Result<()> {
    let conn = database::get_connection()?;
    let now = chrono::Utc::now().to_rfc3339();
    
    // Clear existing session
    conn.execute("DELETE FROM session WHERE id = 1", [])?;
    
    // Create new session
    conn.execute(
        "INSERT INTO session (id, username, logged_in_at) VALUES (1, ?1, ?2)",
        params![username, now],
    )?;
    
    // Update last login
    conn.execute(
        "UPDATE account SET last_login = ?1 WHERE username = ?2",
        params![now, username],
    )?;
    
    Ok(())
}

pub fn get_server_url() -> Result<String> {
    let username = get_current_username()?;
    let conn = database::get_connection()?;
    let server: String = conn.query_row(
        "SELECT server_url FROM account WHERE username = ?1",
        params![username],
        |row| row.get(0),
    )?;
    Ok(server)
}