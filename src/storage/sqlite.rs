use super::Storage;
use crate::domain::*;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use rusqlite::{params, Connection};
use std::sync::Mutex;

pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn new(path: &str) -> Result<Self, ApiError> {
        let conn = Connection::open(path)
            .map_err(|e| ApiError::Internal(format!("failed to open sqlite database: {e}")))?;

        let storage = Self {
            conn: Mutex::new(conn),
        };
        storage.migrate()?;
        Ok(storage)
    }

    fn migrate(&self) -> Result<(), ApiError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        conn.execute_batch(
            r#"
            create table if not exists bots (
                bot_id text primary key,
                api_key_hash text not null,
                secret text not null,
                is_active integer not null default 1,
                created_at text not null default (datetime('now'))
            );

            create table if not exists users (
                user_id text primary key,
                tokens integer not null default 1000,
                tier text not null default 'free',
                is_blocked integer not null default 0,
                blocked_until text,
                created_at text not null default (datetime('now'))
            );

            create table if not exists billing_ledger (
                id integer primary key autoincrement,
                user_id text not null,
                bot_id text not null,
                delta_tokens integer not null,
                balance_after integer not null,
                reason text not null,
                created_at text not null default (datetime('now'))
            );

            create table if not exists blocks (
                id integer primary key autoincrement,
                user_id text not null,
                reason text not null,
                expires_at text not null,
                created_at text not null default (datetime('now'))
            );

            create index if not exists idx_billing_user on billing_ledger(user_id);
            create index if not exists idx_blocks_user on blocks(user_id);
            "#,
        )
        .map_err(|e| ApiError::Internal(format!("sqlite migration failed: {e}")))?;
        Ok(())
    }
}

#[async_trait]
impl Storage for SqliteStorage {
    async fn register_bot(
        &self,
        bot_id: &str,
        api_key_hash: &str,
        secret: &str,
    ) -> Result<Bot, ApiError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let now = Utc::now().to_rfc3339();
        let res = conn.execute(
            "insert into bots (bot_id, api_key_hash, secret, is_active, created_at) values (?1, ?2, ?3, 1, ?4)",
            params![bot_id, api_key_hash, secret, now],
        );
        match res {
            Ok(_) => Ok(Bot {
                bot_id: bot_id.to_string(),
                api_key_hash: api_key_hash.to_string(),
                secret: secret.to_string(),
                is_active: true,
                created_at: now,
            }),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(ApiError::Conflict(format!("bot {bot_id} already exists")))
            }
            Err(e) => Err(ApiError::Internal(e.to_string())),
        }
    }

    async fn get_bot(&self, bot_id: &str) -> Result<Option<Bot>, ApiError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let mut stmt = conn
            .prepare("select bot_id, api_key_hash, secret, is_active, created_at from bots where bot_id = ?1")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let mut rows = stmt
            .query(params![bot_id])
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| ApiError::Internal(e.to_string()))? {
            let active_int: i64 = row.get(3).map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(Some(Bot {
                bot_id: row.get(0).map_err(|e| ApiError::Internal(e.to_string()))?,
                api_key_hash: row.get(1).map_err(|e| ApiError::Internal(e.to_string()))?,
                secret: row.get(2).map_err(|e| ApiError::Internal(e.to_string()))?,
                is_active: active_int == 1,
                created_at: row.get(4).map_err(|e| ApiError::Internal(e.to_string()))?,
            }))
        } else {
            Ok(None)
        }
    }

    async fn rotate_bot_secret(&self, bot_id: &str, new_secret: &str) -> Result<Bot, ApiError> {
        let rows_affected = {
            let conn = self
                .conn
                .lock()
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            conn.execute(
                "update bots set secret = ?1 where bot_id = ?2",
                params![new_secret, bot_id],
            )
            .map_err(|e| ApiError::Internal(e.to_string()))?
        };

        if rows_affected == 0 {
            return Err(ApiError::NotFound(format!("bot {bot_id} not found")));
        }

        self.get_bot(bot_id)
            .await?
            .ok_or_else(|| ApiError::NotFound(format!("bot {bot_id} not found")))
    }

    async fn get_user(&self, user_id: &str) -> Result<User, ApiError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let mut stmt = conn
            .prepare("select user_id, tokens, tier, is_blocked, blocked_until, created_at from users where user_id = ?1")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let mut rows = stmt
            .query(params![user_id])
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| ApiError::Internal(e.to_string()))? {
            let blocked_int: i64 = row.get(3).map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(User {
                user_id: row.get(0).map_err(|e| ApiError::Internal(e.to_string()))?,
                tokens: row.get(1).map_err(|e| ApiError::Internal(e.to_string()))?,
                tier: row.get(2).map_err(|e| ApiError::Internal(e.to_string()))?,
                is_blocked: blocked_int == 1,
                blocked_until: row.get(4).map_err(|e| ApiError::Internal(e.to_string()))?,
                created_at: row.get(5).map_err(|e| ApiError::Internal(e.to_string()))?,
            })
        } else {
            // initialize user with default balance
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "insert into users (user_id, tokens, tier, is_blocked, created_at) values (?1, 1000, 'free', 0, ?2)",
                params![user_id, now],
            )
            .map_err(|e| ApiError::Internal(e.to_string()))?;

            Ok(User {
                user_id: user_id.to_string(),
                tokens: 1000,
                tier: "free".to_string(),
                is_blocked: false,
                blocked_until: None,
                created_at: now,
            })
        }
    }

    async fn consume_tokens(
        &self,
        user_id: &str,
        tokens: i64,
        reason: &str,
        bot_id: &str,
    ) -> Result<ConsumeResponse, ApiError> {
        if tokens <= 0 {
            return Err(ApiError::BadRequest(
                "tokens to consume must be positive".to_string(),
            ));
        }

        let user = self.get_user(user_id).await?;
        if user.is_blocked {
            return Err(ApiError::Forbidden("user is blocked".to_string()));
        }
        if user.tokens < tokens {
            return Err(ApiError::BadRequest(
                "insufficient token balance".to_string(),
            ));
        }

        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let new_balance = user.tokens - tokens;
        conn.execute(
            "update users set tokens = ?1 where user_id = ?2",
            params![new_balance, user_id],
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

        conn.execute(
            "insert into billing_ledger (user_id, bot_id, delta_tokens, balance_after, reason, created_at) values (?1, ?2, ?3, ?4, ?5, ?6)",
            params![user_id, bot_id, -tokens, new_balance, reason, Utc::now().to_rfc3339()],
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

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

        let user = self.get_user(user_id).await?;
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let new_balance = user.tokens + tokens;
        let new_tier = if package == "premium" || package == "pro" {
            package
        } else {
            &user.tier
        };

        conn.execute(
            "update users set tokens = ?1, tier = ?2 where user_id = ?3",
            params![new_balance, new_tier, user_id],
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

        conn.execute(
            "insert into billing_ledger (user_id, bot_id, delta_tokens, balance_after, reason, created_at) values (?1, 'payment_webhook', ?2, ?3, ?4, ?5)",
            params![user_id, tokens, new_balance, format!("purchase:{package}"), Utc::now().to_rfc3339()],
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok(PurchaseResponse {
            status: "success".to_string(),
            user_id: user_id.to_string(),
            new_balance,
        })
    }

    async fn check_block(&self, user_id: &str) -> Result<BlockCheckResponse, ApiError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let mut stmt = conn
            .prepare("select reason, expires_at from blocks where user_id = ?1 and expires_at > ?2 order by id desc limit 1")
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        let now = Utc::now().to_rfc3339();
        let mut rows = stmt
            .query(params![user_id, now])
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        if let Some(row) = rows.next().map_err(|e| ApiError::Internal(e.to_string()))? {
            let reason: String = row.get(0).map_err(|e| ApiError::Internal(e.to_string()))?;
            let expires_at: String = row.get(1).map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok(BlockCheckResponse {
                user_id: user_id.to_string(),
                is_blocked: true,
                reason: Some(reason),
                expires_at: Some(expires_at),
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
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        let expires_at = (Utc::now() + Duration::hours(duration_hours)).to_rfc3339();

        conn.execute(
            "insert into blocks (user_id, reason, expires_at, created_at) values (?1, ?2, ?3, ?4)",
            params![user_id, reason, expires_at, Utc::now().to_rfc3339()],
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

        conn.execute(
            "insert into users (user_id, tokens, tier, is_blocked, blocked_until, created_at)
             values (?1, 1000, 'free', 1, ?2, datetime('now'))
             on conflict(user_id) do update set is_blocked = 1, blocked_until = ?2",
            params![user_id, expires_at],
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok(BlockUserResponse {
            user_id: user_id.to_string(),
            blocked: true,
            expires_at,
        })
    }

    async fn health_check(&self) -> Result<(), ApiError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        conn.execute("select 1", [])
            .map_err(|e| ApiError::Internal(format!("database ping failed: {e}")))?;
        Ok(())
    }
}
