use anyhow::{Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use colored::*;
use dood_encryption::{
    double_ratchet::DoubleRatchet,
    x3dh::{X3DHKeyBundle, X3DH},
};
use reqwest;
use serde_json::json;
use x25519_dalek::PublicKey;

use crate::{auth, database, server};

pub async fn send_message(recipient_username: &str, message: &str) -> Result<()> {
    println!("{}", "🔐 Encrypting message...".cyan());

    let mut sender_x3dh = auth::get_current_x3dh()?;
    let sender_username = auth::get_current_username()?;
    let server_url = auth::get_server_url()?;

    // Search for recipient to get their user_id and device_id
    let (recipient_user_id, recipient_device_id) = search_user(recipient_username).await?;

    // Get or create ratchet state for this conversation
    let mut ratchet_state = get_or_create_ratchet(&mut sender_x3dh, recipient_user_id).await?;

    // Encrypt the message
    let encrypt_result = ratchet_state.ratchet_encrypt(message.as_bytes());

    // Save ratchet state (using username for local storage)
    save_ratchet_state(recipient_username, &ratchet_state)?;

    // Encode for transmission
    let ciphertext_b64 = BASE64_STANDARD.encode(&encrypt_result.cipher_text);
    let header_b64 = BASE64_STANDARD.encode(&encrypt_result.header);

    println!("{}", "📡 Sending to server...".cyan());

    // Send to server
    let client = reqwest::Client::new();
    let body = json!({
        "messages": [{
            "recipient_device_id": recipient_device_id,
            "ciphertext": ciphertext_b64,
            "header": header_b64
        }]
    });

    // Generate challenge for authentication
    let challenge = sender_x3dh.generate_challenge();
    let token = BASE64_STANDARD.encode(&challenge);
    let identity_pub = auth::get_identity_public_key(&sender_x3dh);

    let response = client
        .post(format!("{}/message/send", server_url))
        .json(&body)
        .bearer_auth(&token)
        .header("identity", BASE64_STANDARD.encode(identity_pub.to_bytes()))
        .send()
        .await
        .context("Failed to send message")?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        anyhow::bail!("Failed to send message: {}", error_text);
    }

    // Save to local database
    database::save_message(
        recipient_username,
        &sender_username,
        recipient_username,
        message,
        true,
    )?;

    println!(
        "{} Message sent to {}",
        "✓".green().bold(),
        recipient_username.bold()
    );

    Ok(())
}

async fn search_user(username: &str) -> Result<(u64, u64)> {
    let server_url = auth::get_server_url()?;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/account/search", server_url))
        .query(&[("username", username)])
        .send()
        .await
        .context("Failed to search for user")?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        anyhow::bail!("Failed to search for user: {}", error_text);
    }

    let search_results: serde_json::Value = response.json().await?;
    let users = search_results
        .as_array()
        .context("Expected array of users")?;

    if users.is_empty() {
        anyhow::bail!("User '{}' not found", username);
    }

    // Find exact match
    let user = users
        .iter()
        .find(|u| u["username"].as_str() == Some(username))
        .context(format!("User '{}' not found", username))?;

    let user_id = user["id"].as_u64().context("Missing user id")?;

    let devices = user["Devices"].as_array().context("Missing devices")?;
    if devices.is_empty() {
        anyhow::bail!("User '{}' has no devices", username);
    }

    // Get first device (TODO: support multiple devices)
    let device_id = devices[0]["id"].as_u64().context("Missing device id")?;

    // Store device_id for this user
    store_user_device_mapping(username, user_id, device_id)?;

    Ok((user_id, device_id))
}

fn store_user_device_mapping(username: &str, user_id: u64, device_id: u64) -> Result<()> {
    let conn = database::get_connection()?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_devices (
            username TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            last_updated TEXT NOT NULL
        )",
        [],
    )?;

    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT OR REPLACE INTO user_devices (username, user_id, device_id, last_updated)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![username, user_id, device_id, now],
    )?;

    Ok(())
}

fn get_stored_device_id(username: &str) -> Result<u64> {
    let conn = database::get_connection()?;

    let device_id: u64 = conn.query_row(
        "SELECT device_id FROM user_devices WHERE username = ?1",
        rusqlite::params![username],
        |row| row.get(0),
    )?;

    Ok(device_id)
}

pub async fn fetch_messages() -> Result<()> {
    println!("{}", "📥 Fetching messages...".cyan());

    let mut sender_x3dh = auth::get_current_x3dh()?;
    let current_username = auth::get_current_username()?;
    let server_url = auth::get_server_url()?;

    let client = reqwest::Client::new();

    // Generate challenge for authentication
    let challenge = sender_x3dh.generate_challenge();
    let token = BASE64_STANDARD.encode(&challenge);
    let identity_pub = auth::get_identity_public_key(&sender_x3dh);

    let response = client
        .post(format!("{}/message/fetch", server_url))
        .bearer_auth(&token)
        .header("identity", BASE64_STANDARD.encode(identity_pub.to_bytes()))
        .send()
        .await
        .context("Failed to fetch messages")?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        anyhow::bail!("Failed to fetch messages: {}", error_text);
    }

    let messages: serde_json::Value = response.json().await?;

    // Parse and decrypt messages
    if let Some(messages_array) = messages.as_array() {
        if messages_array.is_empty() {
            println!("{}", "No new messages.".yellow());
            return Ok(());
        }

        println!("{} {} new message(s)", "✓".green(), messages_array.len());

        for msg in messages_array {
            if let Err(e) = process_received_message(&current_username, msg).await {
                eprintln!("{} Failed to process message: {}", "✗".red(), e);
            }
        }
    }

    Ok(())
}

async fn process_received_message(current_username: &str, msg: &serde_json::Value) -> Result<()> {
    // Extract message data
    let ciphertext_b64 = msg["ciphertext"].as_str().context("Missing ciphertext")?;
    let header_b64 = msg["header"].as_str().context("Missing header")?;
    let sender = msg["sender"].as_str().unwrap_or("unknown");

    let ciphertext = BASE64_STANDARD.decode(ciphertext_b64)?;
    let full_header = BASE64_STANDARD.decode(header_b64)?;

    // Split header (first 32 bytes are associated data)
    let associated_data = &full_header[0..32];
    let header = &full_header[32..];

    // Get or load ratchet state
    let mut ratchet_state = load_ratchet_state(sender)?;

    // Decrypt message
    let decrypted = ratchet_state.ratchet_decrypt(header, &ciphertext, associated_data);

    // Save updated ratchet state
    save_ratchet_state(sender, &ratchet_state)?;

    // Save message to database
    database::save_message(sender, sender, current_username, &decrypted, false)?;

    println!("\n{} {} {}", "📨".bold(), "From".cyan(), sender.bold());
    println!("  {}", decrypted);

    Ok(())
}

async fn get_or_create_ratchet(
    sender_x3dh: &mut X3DH,
    recipient_user_id: u64,
) -> Result<DoubleRatchet> {
    // Try to load existing ratchet state (using user_id as key)
    let recipient_key = format!("user_{}", recipient_user_id);
    if let Ok(state) = load_ratchet_state(&recipient_key) {
        return Ok(state);
    }

    // Need to initiate new session
    println!("{}", "🔑 Initiating new encrypted session...".cyan());

    // Fetch recipient's key bundle from server using user_id
    let recipient_bundle_json = server::fetch_key_bundle_by_id(recipient_user_id).await?;

    // Parse the key bundle
    let recipient_bundle = parse_key_bundle(&recipient_bundle_json)?;

    // Perform X3DH key agreement
    let x3dh_result = sender_x3dh.initiate_key_agreement(recipient_bundle);

    // Create new ratchet
    let ratchet = DoubleRatchet::new_sender(
        x3dh_result.rk,
        x3dh_result.alice_dhs,
        x3dh_result.bob_public_key,
    );

    Ok(ratchet)
}

fn parse_key_bundle(response: &serde_json::Value) -> Result<X3DHKeyBundle> {
    // Server returns an array of devices: [{"device_id": 11, "key_bundle": {...}}]
    let devices = response.as_array().context("Expected array of devices")?;

    if devices.is_empty() {
        anyhow::bail!("No devices found for user");
    }

    // Get the first device (TODO: support multiple devices)
    let first_device = &devices[0];
    let bundle_json = &first_device["key_bundle"];

    let identity_key_b64 = bundle_json["identity_key"]
        .as_str()
        .context("Missing identity_key")?;
    let signed_pre_key_b64 = bundle_json["signed_pre_key"]
        .as_str()
        .context("Missing signed_pre_key")?;
    let signature_b64 = bundle_json["signed_pre_key_signature"]
        .as_str()
        .context("Missing signature")?;

    let identity_key_bytes = BASE64_STANDARD.decode(identity_key_b64)?;
    let identity_key: [u8; 32] = identity_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid identity key length"))?;

    let signed_pre_key_bytes = BASE64_STANDARD.decode(signed_pre_key_b64)?;
    let signed_pre_key_array: [u8; 32] = signed_pre_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signed pre key length"))?;
    let signed_pre_key = PublicKey::from(signed_pre_key_array);

    let signature_bytes = BASE64_STANDARD.decode(signature_b64)?;
    let signature: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;

    // Handle optional one-time pre-key
    let one_time_pre_key = bundle_json["one_time_pre_key"]
        .as_str()
        .and_then(|s| BASE64_STANDARD.decode(s).ok())
        .and_then(|bytes| {
            let arr: [u8; 32] = bytes.try_into().ok()?;
            Some(PublicKey::from(arr))
        });

    Ok(X3DHKeyBundle {
        identity_key,
        signed_pre_key,
        signed_pre_key_signature: signature,
        one_time_pre_key,
    })
}

fn save_ratchet_state(username: &str, state: &DoubleRatchet) -> Result<()> {
    let conn = database::get_connection()?;
    let now = chrono::Utc::now().to_rfc3339();

    // Serialize ratchet state using export method
    let state_json = state.export();
    let state_str = serde_json::to_string(&state_json)?;

    conn.execute(
        "INSERT OR REPLACE INTO ratchet_states (username, state_data, last_updated)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![username, state_str, now],
    )?;

    Ok(())
}

fn load_ratchet_state(username: &str) -> Result<DoubleRatchet> {
    let conn = database::get_connection()?;

    let state_str: String = conn.query_row(
        "SELECT state_data FROM ratchet_states WHERE username = ?1",
        rusqlite::params![username],
        |row| row.get(0),
    )?;

    let state_json: serde_json::Value = serde_json::from_str(&state_str)?;
    let state = DoubleRatchet::from(state_json);

    Ok(state)
}
