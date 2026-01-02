use anyhow::{Context, Result};
use base64::{prelude::BASE64_STANDARD, Engine};
use colored::*;
use dood_encryption::{double_ratchet::DoubleRatchet, x3dh::X3DHKeyBundle};
use reqwest;
use serde_json::json;
use x25519_dalek::PublicKey;

use crate::{auth, database, server};

pub async fn send_message(recipient_username: &str, message: &str) -> Result<()> {
    println!("{}", "🔐 Encrypting message...".cyan());

    let mut sender_x3dh = auth::get_current_x3dh()?;
    let sender_username = auth::get_current_username()?;
    let server_url = auth::get_server_url()?;

    let (recipient_user_id, recipient_device_id) = search_user(recipient_username).await?;

    let is_first_message = load_ratchet_state(recipient_username).is_err();

    let (mut ratchet_state, x3dh_metadata) = if is_first_message {
        println!("{}", "🔑 Initiating new encrypted session...".cyan());

        let recipient_bundle_json = server::fetch_key_bundle_by_id(recipient_user_id).await?;
        let recipient_bundle = parse_key_bundle(&recipient_bundle_json)?;

        let x3dh_result = sender_x3dh.initiate_key_agreement(recipient_bundle);

        let metadata = json!({
            "sender_identity": BASE64_STANDARD.encode(x3dh_result.alice_identity_pub.as_bytes()),
            "one_time_pre_key": x3dh_result.bob_one_time_pre_key.map(|k| BASE64_STANDARD.encode(k.as_bytes()))
        });

        let ratchet = DoubleRatchet::new_sender(
            x3dh_result.rk,
            x3dh_result.alice_dhs,
            x3dh_result.bob_public_key,
        );

        (ratchet, Some(metadata))
    } else {
        (load_ratchet_state(recipient_username)?, None)
    };

    let encrypt_result = ratchet_state.ratchet_encrypt(message.as_bytes());

    save_ratchet_state(recipient_username, &ratchet_state)?;

    let header_with_x3dh = if let Some(metadata) = x3dh_metadata {
        let header_json: serde_json::Value = serde_json::from_slice(&encrypt_result.header[32..])
            .context("Failed to parse header JSON")?;

        let mut modified_header = header_json.as_object().unwrap().clone();
        modified_header.insert("x3dh_init".to_string(), metadata);

        let header_bytes = serde_json::to_vec(&modified_header)?;

        let mut full_header = Vec::new();
        full_header.extend_from_slice(&encrypt_result.header[0..32]);
        full_header.extend_from_slice(&header_bytes);

        full_header
    } else {
        encrypt_result.header.clone()
    };

    let ciphertext_b64 = BASE64_STANDARD.encode(&encrypt_result.cipher_text);
    let header_b64 = BASE64_STANDARD.encode(&header_with_x3dh);

    println!("{}", "📡 Sending to server...".cyan());

    let message_obj = json!({
        "recipient_device_id": recipient_device_id,
        "ciphertext": ciphertext_b64,
        "header": header_b64
    });

    let body = json!({
        "messages": [message_obj]
    });

    let challenge = sender_x3dh.generate_challenge();
    let token = BASE64_STANDARD.encode(&challenge);
    let identity_pub = auth::get_identity_public_key(&sender_x3dh);

    let response = reqwest::Client::new()
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

    let user = users
        .iter()
        .find(|u| u["username"].as_str() == Some(username))
        .context(format!("User '{}' not found", username))?;

    let user_id = user["id"].as_u64().context("Missing user id")?;

    let devices = user["Devices"].as_array().context("Missing devices")?;
    if devices.is_empty() {
        anyhow::bail!("User '{}' has no devices", username);
    }

    let device_id = devices[0]["id"].as_u64().context("Missing device id")?;

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

pub async fn fetch_messages() -> Result<()> {
    println!("{}", "📥 Fetching messages...".cyan());

    let mut sender_x3dh = auth::get_current_x3dh()?;
    let current_username = auth::get_current_username()?;
    let server_url = auth::get_server_url()?;

    let client = reqwest::Client::new();

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

    if let Some(messages_array) = messages.as_array() {
        if messages_array.is_empty() {
            println!("{}", "No new messages.".yellow());
            return Ok(());
        }

        let mut new_count = 0;

        for msg in messages_array {
            match process_received_message(&current_username, msg).await {
                Ok(processed) => {
                    if processed {
                        new_count += 1;
                    }
                }
                Err(e) => {
                    eprintln!("{} Failed to process message: {}", "✗".red(), e);
                }
            }
        }

        if new_count == 0 {
            println!("{}", "No new messages.".yellow());
        } else {
            println!("{} {} new message(s)", "✓".green(), new_count);
        }
    }

    Ok(())
}

async fn process_received_message(current_username: &str, msg: &serde_json::Value) -> Result<bool> {
    let ciphertext_b64 = msg["ciphertext"].as_str().context("Missing ciphertext")?;
    let header_b64 = msg["header"].as_str().context("Missing header")?;
    let sender = msg["username"].as_str().unwrap_or("unknown");

    let ciphertext = BASE64_STANDARD.decode(ciphertext_b64)?;
    let full_header = BASE64_STANDARD.decode(header_b64)?;

    let associated_data = &full_header[0..32];
    let header = &full_header[32..];

    let header_json: serde_json::Value =
        serde_json::from_slice(header).context("Failed to parse header JSON")?;

    let parsed_header = DoubleRatchet::read_header(header);
    let alice_dh_public = PublicKey::from(parsed_header.public_key);

    if let Ok(ratchet_state) = load_ratchet_state(sender) {
        if is_old_message(&ratchet_state, &parsed_header, &alice_dh_public) {
            return Ok(false);
        }
    }

    let mut ratchet_state =
        get_or_initialize_receiver_ratchet(sender, &header_json, alice_dh_public).await?;

    let decrypted = ratchet_state.ratchet_decrypt(header, &ciphertext, associated_data);

    save_ratchet_state(sender, &ratchet_state)?;

    database::save_message(sender, sender, current_username, &decrypted, false)?;

    println!("\n{} {} {}", "📨".bold(), "From".cyan(), sender.bold());
    println!("  {}", decrypted);

    Ok(true)
}

fn is_old_message(
    ratchet_state: &DoubleRatchet,
    header: &dood_encryption::double_ratchet::ParsedHeader,
    header_dh_public: &PublicKey,
) -> bool {
    if ratchet_state.dh_public_r.to_bytes() == header_dh_public.to_bytes() {
        if header.n < ratchet_state.nr {
            return true;
        }
    }

    for skipped in &ratchet_state.mk_skipped {
        if skipped.public_key == header.public_key && skipped.n == header.n {
            return true;
        }
    }

    false
}

async fn get_or_initialize_receiver_ratchet(
    sender: &str,
    header_json: &serde_json::Value,
    alice_dh_public: PublicKey,
) -> Result<DoubleRatchet> {
    if let Ok(state) = load_ratchet_state(sender) {
        return Ok(state);
    }

    println!(
        "{}",
        "🔑 Initializing new encrypted session as receiver...".cyan()
    );

    let mut receiver_x3dh = auth::get_current_x3dh()?;

    let x3dh_init = header_json["x3dh_init"]
        .as_object()
        .context("Missing x3dh_init in first message header")?;

    let sender_identity_b64 = x3dh_init["sender_identity"]
        .as_str()
        .context("Missing sender_identity")?;

    let sender_identity_bytes = BASE64_STANDARD.decode(sender_identity_b64)?;
    let alice_identity: [u8; 32] = sender_identity_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid sender identity length"))?;
    let alice_identity_pub = PublicKey::from(alice_identity);

    let one_time_pre_key = x3dh_init["one_time_pre_key"]
        .as_str()
        .and_then(|s| BASE64_STANDARD.decode(s).ok())
        .and_then(|bytes| {
            let arr: [u8; 32] = bytes.try_into().ok()?;
            Some(PublicKey::from(arr))
        });

    let shared_key = receiver_x3dh.respond_to_key_agreement(
        alice_identity_pub,
        alice_dh_public,
        one_time_pre_key,
    );

    let bob_dh_keypair = receiver_x3dh.get_pre_key_pair();

    let ratchet = DoubleRatchet::new_receiver(shared_key, bob_dh_keypair, alice_dh_public);

    Ok(ratchet)
}

fn parse_key_bundle(response: &serde_json::Value) -> Result<X3DHKeyBundle> {
    let devices = response.as_array().context("Expected array of devices")?;

    if devices.is_empty() {
        anyhow::bail!("No devices found for user");
    }

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
    let current_user = auth::get_current_username()?;
    let now = chrono::Utc::now().to_rfc3339();

    let state_json = state.export();
    let state_str = serde_json::to_string(&state_json)?;

    // Use composite key: current_user:conversation_partner
    let key = format!("{}:{}", current_user, username);

    conn.execute(
        "INSERT OR REPLACE INTO ratchet_states (username, state_data, last_updated)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![key, state_str, now],
    )?;

    Ok(())
}

fn load_ratchet_state(username: &str) -> Result<DoubleRatchet> {
    let conn = database::get_connection()?;
    let current_user = auth::get_current_username()?;

    let key = format!("{}:{}", current_user, username);

    let state_str: String = conn.query_row(
        "SELECT state_data FROM ratchet_states WHERE username = ?1",
        rusqlite::params![key],
        |row| row.get(0),
    )?;

    let state_json: serde_json::Value = serde_json::from_str(&state_str)?;
    let state = DoubleRatchet::from(state_json);

    Ok(state)
}
