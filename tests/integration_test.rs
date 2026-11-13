use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use kepchuk::api::create_router;
use kepchuk::api::middleware::AppState;
use kepchuk::crypto;
use kepchuk::domain::*;
use kepchuk::nonce::memory::MemoryNonceStore;
use kepchuk::storage::memory::MemoryStorage;
use kepchuk::storage::sqlite::SqliteStorage;
use kepchuk::storage::Storage;
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use uuid::Uuid;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn sign_request(
    bot_id: &str,
    bot_secret: &str,
    timestamp: u64,
    nonce: &str,
    body: &[u8],
) -> String {
    let body_sha256_hex = crypto::sha256_hex(body);
    let time_window = timestamp / 300;
    let message = format!("{bot_id}:{timestamp}:{nonce}:{body_sha256_hex}");
    let signed_payload = format!("{time_window}:{message}");
    crypto::hmac_sha256_hex(bot_secret.as_bytes(), signed_payload.as_bytes())
}

fn build_test_app(storage: Arc<dyn Storage>) -> axum::Router {
    let nonce = Arc::new(MemoryNonceStore::new());
    let state = AppState { storage, nonce };
    create_router(state)
}

#[tokio::test]
async fn test_health_and_readiness() {
    let storage = Arc::new(MemoryStorage::new());
    let app = build_test_app(storage);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_bot_registration_and_three_level_auth() {
    let storage = Arc::new(MemoryStorage::new());
    let app = build_test_app(storage);

    // 1. register bot
    let reg_body = json!({ "bot_id": "anime_girl" }).to_string();
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/auth/register")
                .header("Content-Type", "application/json")
                .body(Body::from(reg_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let reg_json: BotRegistrationResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reg_json.bot_id, "anime_girl");
    let api_key = reg_json.api_key;
    let bot_secret = reg_json.bot_secret;

    // 2. test missing auth header (level 1 failure)
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/kep/subs/status/user_123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 3. test expired timestamp (level 2 ttl failure)
    let expired_ts = now_secs() - 400; // >300s old
    let nonce = Uuid::new_v4().to_string();
    let sig = sign_request("anime_girl", &bot_secret, expired_ts, &nonce, b"");

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/kep/subs/status/user_123")
                .header("X-Bot-ID", "anime_girl")
                .header("X-API-Key", &api_key)
                .header("X-Timestamp", expired_ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", sig)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 4. test invalid signature (level 2 crypto failure)
    let ts = now_secs();
    let nonce = Uuid::new_v4().to_string();
    let bad_sig = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/kep/subs/status/user_123")
                .header("X-Bot-ID", "anime_girl")
                .header("X-API-Key", &api_key)
                .header("X-Timestamp", ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", bad_sig)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

    // 5. valid signed request to get user balance
    let valid_sig = sign_request("anime_girl", &bot_secret, ts, &nonce, b"");
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/kep/subs/status/user_123")
                .header("X-Bot-ID", "anime_girl")
                .header("X-API-Key", &api_key)
                .header("X-Timestamp", ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", valid_sig)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let user_status: UserStatusResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(user_status.tokens, 1000);

    // 6. test replay attack with identical nonce (level 3 failure)
    let replay_sig = sign_request("anime_girl", &bot_secret, ts, &nonce, b"");
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/kep/subs/status/user_123")
                .header("X-Bot-ID", "anime_girl")
                .header("X-API-Key", &api_key)
                .header("X-Timestamp", ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", replay_sig)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_billing_consume_and_purchase() {
    let storage = Arc::new(MemoryStorage::new());
    let app = build_test_app(storage);

    // register bot
    let reg_body = json!({ "bot_id": "billing_bot" }).to_string();
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/auth/register")
                .header("Content-Type", "application/json")
                .body(Body::from(reg_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let reg: BotRegistrationResponse = serde_json::from_slice(&bytes).unwrap();

    // consume 150 tokens
    let consume_body = json!({
        "user_id": "client_99",
        "tokens": 150,
        "reason": "chat_message"
    })
    .to_string();

    let ts = now_secs();
    let nonce = Uuid::new_v4().to_string();
    let sig = sign_request(
        "billing_bot",
        &reg.bot_secret,
        ts,
        &nonce,
        consume_body.as_bytes(),
    );

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/subs/consume")
                .header("Content-Type", "application/json")
                .header("X-Bot-ID", "billing_bot")
                .header("X-API-Key", &reg.api_key)
                .header("X-Timestamp", ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", sig)
                .body(Body::from(consume_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let consume_res: ConsumeResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(consume_res.status, "success");
    assert_eq!(consume_res.new_balance, 850);

    // purchase 500 tokens via payment webhook
    let purchase_body = json!({
        "user_id": "client_99",
        "package": "pro",
        "tokens": 500
    })
    .to_string();

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/subs/purchase")
                .header("Content-Type", "application/json")
                .body(Body::from(purchase_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let purchase_res: PurchaseResponse = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(purchase_res.new_balance, 1350);
}

#[tokio::test]
async fn test_user_blocking_and_enforcement() {
    let storage = Arc::new(MemoryStorage::new());
    let app = build_test_app(storage);

    // register bot
    let reg_body = json!({ "bot_id": "guard_bot" }).to_string();
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/auth/register")
                .header("Content-Type", "application/json")
                .body(Body::from(reg_body))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let reg: BotRegistrationResponse = serde_json::from_slice(&bytes).unwrap();

    // block user
    let block_body = json!({
        "user_id": "spammer_42",
        "reason": "rate_limit_violation",
        "duration_hours": 24
    })
    .to_string();

    let ts = now_secs();
    let nonce = Uuid::new_v4().to_string();
    let sig = sign_request(
        "guard_bot",
        &reg.bot_secret,
        ts,
        &nonce,
        block_body.as_bytes(),
    );

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/block/user")
                .header("Content-Type", "application/json")
                .header("X-Bot-ID", "guard_bot")
                .header("X-API-Key", &reg.api_key)
                .header("X-Timestamp", ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", sig)
                .body(Body::from(block_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // check block endpoint
    let ts = now_secs();
    let nonce = Uuid::new_v4().to_string();
    let sig = sign_request("guard_bot", &reg.bot_secret, ts, &nonce, b"");

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/kep/block/check/spammer_42")
                .header("X-Bot-ID", "guard_bot")
                .header("X-API-Key", &reg.api_key)
                .header("X-Timestamp", ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", sig)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let check: BlockCheckResponse = serde_json::from_slice(&bytes).unwrap();
    assert!(check.is_blocked);
    assert_eq!(check.reason.as_deref(), Some("rate_limit_violation"));

    // attempt consume for blocked user
    let consume_body = json!({
        "user_id": "spammer_42",
        "tokens": 10,
        "reason": "message"
    })
    .to_string();

    let ts = now_secs();
    let nonce = Uuid::new_v4().to_string();
    let sig = sign_request(
        "guard_bot",
        &reg.bot_secret,
        ts,
        &nonce,
        consume_body.as_bytes(),
    );

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/subs/consume")
                .header("Content-Type", "application/json")
                .header("X-Bot-ID", "guard_bot")
                .header("X-API-Key", &reg.api_key)
                .header("X-Timestamp", ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", sig)
                .body(Body::from(consume_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_sqlite_persistence() {
    let db_path = format!("test_{}.db", Uuid::new_v4().simple());
    let storage = Arc::new(SqliteStorage::new(&db_path).unwrap());
    let app = build_test_app(storage);

    // register bot on sqlite
    let reg_body = json!({ "bot_id": "sqlite_bot" }).to_string();
    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/auth/register")
                .header("Content-Type", "application/json")
                .body(Body::from(reg_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let reg: BotRegistrationResponse = serde_json::from_slice(&bytes).unwrap();

    // heartbeat
    let hb_body = json!({ "status": "online", "load": 0.12 }).to_string();
    let ts = now_secs();
    let nonce = Uuid::new_v4().to_string();
    let sig = sign_request(
        "sqlite_bot",
        &reg.bot_secret,
        ts,
        &nonce,
        hb_body.as_bytes(),
    );

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/kep/bot/heartbeat")
                .header("Content-Type", "application/json")
                .header("X-Bot-ID", "sqlite_bot")
                .header("X-API-Key", &reg.api_key)
                .header("X-Timestamp", ts.to_string())
                .header("X-Nonce", &nonce)
                .header("X-Signature", sig)
                .body(Body::from(hb_body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(res.status(), StatusCode::OK);

    // cleanup test db file
    let _ = std::fs::remove_file(db_path);
}
