pub mod memory;
pub mod sqlite;

use crate::domain::*;
use async_trait::async_trait;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn register_bot(
        &self,
        bot_id: &str,
        api_key_hash: &str,
        secret: &str,
    ) -> Result<Bot, ApiError>;

    async fn get_bot(&self, bot_id: &str) -> Result<Option<Bot>, ApiError>;

    async fn rotate_bot_secret(&self, bot_id: &str, new_secret: &str) -> Result<Bot, ApiError>;

    async fn get_user(&self, user_id: &str) -> Result<User, ApiError>;

    async fn consume_tokens(
        &self,
        user_id: &str,
        tokens: i64,
        reason: &str,
        bot_id: &str,
    ) -> Result<ConsumeResponse, ApiError>;

    async fn purchase_tokens(
        &self,
        user_id: &str,
        package: &str,
        tokens: i64,
    ) -> Result<PurchaseResponse, ApiError>;

    async fn check_block(&self, user_id: &str) -> Result<BlockCheckResponse, ApiError>;

    async fn block_user(
        &self,
        user_id: &str,
        reason: &str,
        duration_hours: i64,
    ) -> Result<BlockUserResponse, ApiError>;

    async fn health_check(&self) -> Result<(), ApiError>;
}
