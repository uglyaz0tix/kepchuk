use crate::api::middleware::AppState;
use crate::domain::*;
use axum::{
    extract::{Path, State},
    Json,
};

pub async fn check_user_block_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<BlockCheckResponse>, ApiError> {
    let resp = state.storage.check_block(&user_id).await?;
    Ok(Json(resp))
}

pub async fn block_user_handler(
    State(state): State<AppState>,
    Json(payload): Json<BlockUserRequest>,
) -> Result<Json<BlockUserResponse>, ApiError> {
    let resp = state
        .storage
        .block_user(&payload.user_id, &payload.reason, payload.duration_hours)
        .await?;

    Ok(Json(resp))
}
