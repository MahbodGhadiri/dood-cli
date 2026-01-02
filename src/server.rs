use anyhow::{Context, Result};
use reqwest;

use crate::auth;

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
