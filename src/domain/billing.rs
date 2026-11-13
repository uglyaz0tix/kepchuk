use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumeRequest {
    pub user_id: String,
    pub tokens: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumeResponse {
    pub status: String,
    pub new_balance: i64,
    pub notify_owner: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseRequest {
    pub user_id: String,
    pub package: String,
    pub tokens: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurchaseResponse {
    pub status: String,
    pub user_id: String,
    pub new_balance: i64,
}
