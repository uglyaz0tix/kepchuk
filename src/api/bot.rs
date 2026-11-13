use crate::api::middleware::AppState;
use crate::domain::*;
use axum::{
    extract::{Path, State},
    Json,
};

pub async fn bot_heartbeat_handler(
    State(_state): State<AppState>,
    Json(_payload): Json<BotHeartbeatRequest>,
) -> Result<Json<BotHeartbeatResponse>, ApiError> {
    Ok(Json(BotHeartbeatResponse {
        status: "alive".to_string(),
        acknowledged: true,
    }))
}

pub async fn get_bot_config_handler(
    State(state): State<AppState>,
    Path(bot_id): Path<String>,
) -> Result<Json<BotConfigResponse>, ApiError> {
    let _ = state
        .storage
        .get_bot(&bot_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("bot {bot_id} not found")))?;

    Ok(Json(BotConfigResponse {
        bot_id,
        max_tokens_per_request: 2000,
        enabled_features: vec![
            "chat".to_string(),
            "voice".to_string(),
            "vision".to_string(),
        ],
    }))
}
