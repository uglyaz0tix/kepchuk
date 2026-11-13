use super::NonceStore;
use async_trait::async_trait;
use dashmap::DashMap;
use std::time::{Duration, Instant};

pub struct MemoryNonceStore {
    entries: DashMap<(String, String), Instant>,
}

impl Default for MemoryNonceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryNonceStore {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    pub fn cleanup_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, &mut expiry| expiry > now);
    }
}

#[async_trait]
impl NonceStore for MemoryNonceStore {
    async fn check_and_record(&self, bot_id: &str, nonce: &str, ttl_seconds: u64) -> bool {
        self.cleanup_expired();
        let key = (bot_id.to_string(), nonce.to_string());
        let now = Instant::now();

        if let Some(entry) = self.entries.get(&key) {
            if *entry > now {
                return false;
            }
        }

        let expiry = now + Duration::from_secs(ttl_seconds);
        self.entries.insert(key, expiry);
        true
    }
}
