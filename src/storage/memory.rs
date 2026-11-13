use super::Storage;
use crate::domain::*;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Default)]
pub struct MemoryStorage {
    bots: RwLock<HashMap<String, Bot>>,
    users: RwLock<HashMap<String, User>>,
    blocks: RwLock<HashMap<String, (String, String)>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn register_bot(
        &self,
        bot_id: &str,
        api_key_hash: &str,
        secret: &str,
    ) -> Result<Bot, ApiError> {
        let mut bots = self
            .bots
            .write()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        if bots.contains_key(bot_id) {
            return Err(ApiError::Conflict(format!("bot {bot_id} already exists")));
        }
        let bot = Bot {
            bot_id: bot_id.to_string(),
            api_key_hash: api_key_hash.to_string(),
            secret: secret.to_string(),
            is_active: true,
            created_at: Utc::now().to_rfc3339(),
        };
        bots.insert(bot_id.to_string(), bot.clone());
        Ok(bot)
    }

    async fn get_bot(&self, bot_id: &str) -> Result<Option<Bot>, ApiError> {
        let bots = self
            .bots
            .read()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(bots.get(bot_id).cloned())
    }

    async fn rotate_bot_secret(&self, bot_id: &str, new_secret: &str) -> Result<Bot, ApiError> {
        let mut bots = self
            .bots
            .write()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let bot = bots
            .get_mut(bot_id)
            .ok_or_else(|| ApiError::NotFound(format!("bot {bot_id} not found")))?;
        bot.secret = new_secret.to_string();
        Ok(bot.clone())
    }

    async fn get_user(&self, user_id: &str) -> Result<User, ApiError> {
        let mut users = self
            .users
            .write()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let user = users
            .entry(user_id.to_string())
            .or_insert_with(|| User {
                user_id: user_id.to_string(),
                tokens: 1000,
                tier: "free".to_string(),
                is_blocked: false,
                blocked_until: None,
                created_at: Utc::now().to_rfc3339(),
            })
            .clone();
        Ok(user)
    }

    async fn consume_tokens(
        &self,
        user_id: &str,
        tokens: i64,
        _reason: &str,
        _bot_id: &str,
    ) -> Result<ConsumeResponse, ApiError> {
        if tokens <= 0 {
            return Err(ApiError::BadRequest(
                "tokens to consume must be positive".to_string(),
            ));
        }

        let mut users = self
            .users
            .write()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let user = users.entry(user_id.to_string()).or_insert_with(|| User {
            user_id: user_id.to_string(),
            tokens: 1000,
            tier: "free".to_string(),
            is_blocked: false,
            blocked_until: None,
            created_at: Utc::now().to_rfc3339(),
        });

        if user.is_blocked {
            return Err(ApiError::Forbidden("user is blocked".to_string()));
        }

        if user.tokens < tokens {
            return Err(ApiError::BadRequest(
                "insufficient token balance".to_string(),
            ));
        }

        user.tokens -= tokens;
        let new_balance = user.tokens;
        let notify_owner = new_balance < 100;

        Ok(ConsumeResponse {
            status: "success".to_string(),
            new_balance,
            notify_owner,
        })
    }

    async fn purchase_tokens(
        &self,
        user_id: &str,
        package: &str,
        tokens: i64,
    ) -> Result<PurchaseResponse, ApiError> {
        if tokens <= 0 {
            return Err(ApiError::BadRequest(
                "tokens purchased must be positive".to_string(),
            ));
        }

        let mut users = self
            .users
            .write()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let user = users.entry(user_id.to_string()).or_insert_with(|| User {
            user_id: user_id.to_string(),
            tokens: 1000,
            tier: "free".to_string(),
            is_blocked: false,
            blocked_until: None,
            created_at: Utc::now().to_rfc3339(),
        });

        user.tokens += tokens;
        if package == "premium" || package == "pro" {
            user.tier = package.to_string();
        }

        Ok(PurchaseResponse {
            status: "success".to_string(),
            user_id: user_id.to_string(),
            new_balance: user.tokens,
        })
    }

    async fn check_block(&self, user_id: &str) -> Result<BlockCheckResponse, ApiError> {
        let blocks = self
            .blocks
            .read()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        if let Some((reason, expires_at)) = blocks.get(user_id) {
            Ok(BlockCheckResponse {
                user_id: user_id.to_string(),
                is_blocked: true,
                reason: Some(reason.clone()),
                expires_at: Some(expires_at.clone()),
            })
        } else {
            Ok(BlockCheckResponse {
                user_id: user_id.to_string(),
                is_blocked: false,
                reason: None,
                expires_at: None,
            })
        }
    }

    async fn block_user(
        &self,
        user_id: &str,
        reason: &str,
        duration_hours: i64,
    ) -> Result<BlockUserResponse, ApiError> {
        let expires_at = (Utc::now() + Duration::hours(duration_hours)).to_rfc3339();
        let mut blocks = self
            .blocks
            .write()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        blocks.insert(
            user_id.to_string(),
            (reason.to_string(), expires_at.clone()),
        );

        let mut users = self
            .users
            .write()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let user = users.entry(user_id.to_string()).or_insert_with(|| User {
            user_id: user_id.to_string(),
            tokens: 1000,
            tier: "free".to_string(),
            is_blocked: false,
            blocked_until: None,
            created_at: Utc::now().to_rfc3339(),
        });
        user.is_blocked = true;
        user.blocked_until = Some(expires_at.clone());

        Ok(BlockUserResponse {
            user_id: user_id.to_string(),
            blocked: true,
            expires_at,
        })
    }

    async fn health_check(&self) -> Result<(), ApiError> {
        Ok(())
    }
}
