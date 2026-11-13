use super::auth::*;
use super::block::*;
use super::bot::*;
use super::middleware::{auth_middleware, AppState};
use super::subs::*;
use crate::domain::ApiError;
use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<&'static str, ApiError> {
    state.storage.health_check().await?;
    Ok("ready")
}

pub fn create_router(state: AppState) -> Router {
    let protected_routes = Router::new()
        .route("/kep/auth/rotate", post(rotate_bot_secret_handler))
        .route("/kep/subs/status/:user_id", get(get_user_status_handler))
        .route("/kep/subs/consume", post(consume_tokens_handler))
        .route("/kep/block/check/:user_id", get(check_user_block_handler))
        .route("/kep/block/user", post(block_user_handler))
        .route("/kep/bot/heartbeat", post(bot_heartbeat_handler))
        .route("/kep/bot/config/:bot_id", get(get_bot_config_handler))
        .route_layer(from_fn_with_state(state.clone(), auth_middleware));

    let public_routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/kep/auth/register", post(register_bot_handler))
        .route("/kep/subs/purchase", post(purchase_tokens_handler));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
