pub mod memory;

use async_trait::async_trait;

#[async_trait]
pub trait NonceStore: Send + Sync {
    async fn check_and_record(&self, bot_id: &str, nonce: &str, ttl_seconds: u64) -> bool;
}
