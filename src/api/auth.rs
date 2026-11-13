use crate::api::middleware::AppState;
use crate::crypto;
use crate::domain::*;
use axum::{
    extract::{Extension, State},
    Json,
};
use uuid::Uuid;

pub async fn register_bot_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterBotRequest>,
) -> Result<Json<BotRegistrationResponse>, ApiError> {
    if payload.bot_id.trim().is_empty() {
        return Err(ApiError::BadRequest("bot_id cannot be empty".to_string()));
    }

    // generate random keys
    let raw_api_key = format!(
        "ak_live_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    let raw_secret = format!("sec_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let api_key_hash = crypto::sha256_hex(raw_api_key.as_bytes());

    state
        .storage
        .register_bot(&payload.bot_id, &api_key_hash, &raw_secret)
        .await?;

    Ok(Json(BotRegistrationResponse {
        bot_id: payload.bot_id,
        api_key: raw_api_key,
        bot_secret: raw_secret,
    }))
}

pub async fn rotate_bot_secret_handler(
    State(state): State<AppState>,
    Extension(bot): Extension<Bot>,
) -> Result<Json<RotateSecretResponse>, ApiError> {
    let new_secret = format!("sec_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let updated = state
        .storage
        .rotate_bot_secret(&bot.bot_id, &new_secret)
        .await?;

    Ok(Json(RotateSecretResponse {
        bot_id: updated.bot_id,
        bot_secret: updated.secret,
    }))
}
