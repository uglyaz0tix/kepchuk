use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bot {
    pub bot_id: String,
    pub api_key_hash: String,
    pub secret: String,
    pub is_active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotRegistrationResponse {
    pub bot_id: String,
    pub api_key: String,
    pub bot_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterBotRequest {
    pub bot_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSecretResponse {
    pub bot_id: String,
    pub bot_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotHeartbeatRequest {
    pub status: String,
    pub load: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotHeartbeatResponse {
    pub status: String,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotConfigResponse {
    pub bot_id: String,
    pub max_tokens_per_request: i64,
    pub enabled_features: Vec<String>,
}
