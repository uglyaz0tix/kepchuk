use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub tokens: i64,
    pub tier: String,
    pub is_blocked: bool,
    pub blocked_until: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStatusResponse {
    pub user_id: String,
    pub tokens: i64,
    pub tier: String,
    pub is_blocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockCheckResponse {
    pub user_id: String,
    pub is_blocked: bool,
    pub reason: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockUserRequest {
    pub user_id: String,
    pub reason: String,
    pub duration_hours: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockUserResponse {
    pub user_id: String,
    pub blocked: bool,
    pub expires_at: String,
}
