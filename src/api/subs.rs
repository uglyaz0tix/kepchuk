use crate::api::middleware::AppState;
use crate::domain::*;
use axum::{
    extract::{Extension, Path, State},
    Json,
};

pub async fn get_user_status_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<UserStatusResponse>, ApiError> {
    let user = state.storage.get_user(&user_id).await?;
    Ok(Json(UserStatusResponse {
        user_id: user.user_id,
        tokens: user.tokens,
        tier: user.tier,
        is_blocked: user.is_blocked,
    }))
}

pub async fn consume_tokens_handler(
    State(state): State<AppState>,
    Extension(bot): Extension<Bot>,
    Json(payload): Json<ConsumeRequest>,
) -> Result<Json<ConsumeResponse>, ApiError> {
    let resp = state
        .storage
        .consume_tokens(
            &payload.user_id,
            payload.tokens,
            &payload.reason,
            &bot.bot_id,
        )
        .await?;

    Ok(Json(resp))
}

pub async fn purchase_tokens_handler(
    State(state): State<AppState>,
    Json(payload): Json<PurchaseRequest>,
) -> Result<Json<PurchaseResponse>, ApiError> {
    let resp = state
        .storage
        .purchase_tokens(&payload.user_id, &payload.package, payload.tokens)
        .await?;

    Ok(Json(resp))
}
