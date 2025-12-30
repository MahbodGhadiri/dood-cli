use anyhow::{Context, Result};
use reqwest;
use serde_json::Value;

use crate::auth;

pub async fn fetch_key_bundle(username: &str) -> Result<Value> {
    let server_url = auth::get_server_url()?;
    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "{}/account/key-bundle?user_id={}",
            server_url, username
        ))
        .send()
        .await
        .context("Failed to fetch key bundle")?;

    if !response.status().is_success() {
        anyhow::bail!(
            "User '{}' Key Bundle not found - Error: {}",
            username,
            response.text().await?
        );
    }

    let bundle: Value = response.json().await?;
    Ok(bundle)
}

pub async fn get_user_info(username: &str) -> Result<Value> {
    let server_url = auth::get_server_url()?;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("{}/account/info/{}", server_url, username))
        .send()
        .await
        .context("Failed to fetch user info")?;

    if !response.status().is_success() {
        anyhow::bail!("User '{}' not found", username);
    }

    let info: Value = response.json().await?;
    Ok(info)
}

pub async fn fetch_key_bundle_by_id(user_id: u64) -> Result<serde_json::Value> {
    let server_url = auth::get_server_url()?;
    let client = reqwest::Client::new();

    let response = client
        .get(format!(
            "{}/account/key-bundle?user_id={}",
            server_url, user_id
        ))
        .send()
        .await
        .context("Failed to fetch key bundle")?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        anyhow::bail!("Failed to fetch key bundle: {}", error_text);
    }

    let bundle = response.json().await?;
    Ok(bundle)
}
