use crate::crypto;
use crate::domain::{ApiError, Bot};
use crate::nonce::NonceStore;
use crate::storage::Storage;
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub nonce: Arc<dyn NonceStore>,
}

pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let bot_id = req
        .headers()
        .get("X-Bot-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError::Unauthorized("missing X-Bot-ID header".to_string()))?;

    let api_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError::Unauthorized("missing X-API-Key header".to_string()))?;

    let timestamp_str = req
        .headers()
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing X-Timestamp header".to_string()))?;

    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| ApiError::Unauthorized("invalid X-Timestamp".to_string()))?;

    let signature = req
        .headers()
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError::Unauthorized("missing X-Signature header".to_string()))?;

    let nonce = req
        .headers()
        .get("X-Nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| ApiError::Unauthorized("missing X-Nonce header".to_string()))?;

    // level 1: verify api key against storage
    let bot: Bot = state
        .storage
        .get_bot(&bot_id)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("bot not found".to_string()))?;

    if !bot.is_active {
        return Err(ApiError::Unauthorized("bot is deactivated".to_string()));
    }

    let calculated_api_key_hash = crypto::sha256_hex(api_key.as_bytes());
    if !crypto::secure_compare(
        bot.api_key_hash.as_bytes(),
        calculated_api_key_hash.as_bytes(),
    ) {
        return Err(ApiError::Unauthorized("invalid api key".to_string()));
    }

    // level 2: verify timestamp ttl window 300 seconds
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ApiError::Internal(e.to_string()))?
        .as_secs();

    if (now as i64 - timestamp as i64).abs() > 300 {
        return Err(ApiError::Unauthorized("signature expired".to_string()));
    }

    // buffer request body for payload hashing
    let (parts, body) = req.into_parts();
    let body_bytes = to_bytes(body, 2 * 1024 * 1024)
        .await
        .map_err(|e| ApiError::BadRequest(format!("failed to read body: {e}")))?;

    let body_sha256_hex = crypto::sha256_hex(&body_bytes);
    let time_window = timestamp / 300;
    let message = format!("{bot_id}:{timestamp}:{nonce}:{body_sha256_hex}");
    let signed_payload = format!("{time_window}:{message}");

    let expected_sig = crypto::hmac_sha256_hex(bot.secret.as_bytes(), signed_payload.as_bytes());
    if !crypto::secure_compare(
        expected_sig.to_lowercase().as_bytes(),
        signature.to_lowercase().as_bytes(),
    ) {
        return Err(ApiError::Unauthorized("invalid signature".to_string()));
    }

    // level 3: verify nonce anti-replay
    if !state.nonce.check_and_record(&bot_id, &nonce, 300).await {
        return Err(ApiError::Conflict(
            "replay detected: nonce already used".to_string(),
        ));
    }

    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(bot);

    Ok(next.run(req).await)
}
