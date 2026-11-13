# KepchukAPI Reference Documentation

The Kepchuk Central Server (CS) provides authentication, token accounting, billing, and safety enforcement for AI character bots.

## Authentication Overview

All protected endpoints require 5 mandatory request headers:
- `X-Bot-ID`: Identifier of the registered bot.
- `X-API-Key`: Secret API key (`ak_live_...`).
- `X-Timestamp`: Unix epoch timestamp in seconds.
- `X-Nonce`: Single-use unique identifier (UUID v4 or random hex string).
- `X-Signature`: HMAC-SHA256 signature (in hex) calculated as:

```text
time_window = timestamp / 300
message = bot_id + ":" + timestamp + ":" + nonce + ":" + sha256_hex(request_body)
signature = HMAC_SHA256(bot_secret, time_window + ":" + message)
```

For GET requests or requests with empty bodies, `sha256_hex("")` is:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

---

## 1. System Endpoints

### `GET /healthz`
Liveness probe.
- **Auth**: None
- **Response**: `200 OK` (`ok`)

### `GET /readyz`
Readiness probe verifying database connectivity.
- **Auth**: None
- **Response**: `200 OK` (`ready`)

---

## 2. Authentication (`/kep/auth`)

### `POST /kep/auth/register`
Registers a new bot identity. Returns the credentials once.
- **Auth**: None
- **Request Body**:
  ```json
  {
    "bot_id": "anime_girl"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "bot_id": "anime_girl",
    "api_key": "ak_live_...",
    "bot_secret": "sec_..."
  }
  ```

### `POST /kep/auth/rotate`
Rotates the secret key of an existing bot.
- **Auth**: Required (Level 1, 2, 3)
- **Response `200 OK`**:
  ```json
  {
    "bot_id": "anime_girl",
    "bot_secret": "sec_new_..."
  }
  ```

---

## 3. Subscriptions & Billing (`/kep/subs`)

### `GET /kep/subs/status/:user_id`
Retrieves token balance, tier, and status for a specific user.
- **Auth**: Required
- **Response `200 OK`**:
  ```json
  {
    "user_id": "user_123",
    "tokens": 1000,
    "tier": "free",
    "is_blocked": false
  }
  ```

### `POST /kep/subs/consume`
Debits tokens from a user account for service usage.
- **Auth**: Required
- **Request Body**:
  ```json
  {
    "user_id": "user_123",
    "tokens": 150,
    "reason": "chat_message"
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "status": "success",
    "new_balance": 850,
    "notify_owner": false
  }
  ```
- **Error Responses**:
  - `400 Bad Request` if insufficient balance or negative tokens.
  - `403 Forbidden` if user is blocked.

### `POST /kep/subs/purchase`
Webhook from payment gateways to deposit tokens.
- **Auth**: Public Webhook
- **Request Body**:
  ```json
  {
    "user_id": "user_123",
    "package": "pro",
    "tokens": 500
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "status": "success",
    "user_id": "user_123",
    "new_balance": 1350
  }
  ```

---

## 4. Moderation & Blocks (`/kep/block`)

### `GET /kep/block/check/:user_id`
Checks if a user is currently banned.
- **Auth**: Required
- **Response `200 OK`**:
  ```json
  {
    "user_id": "user_123",
    "is_blocked": true,
    "reason": "spam",
    "expires_at": "2026-11-14T10:00:00Z"
  }
  ```

### `POST /kep/block/user`
Bans a user for a given duration.
- **Auth**: Required
- **Request Body**:
  ```json
  {
    "user_id": "user_123",
    "reason": "terms_violation",
    "duration_hours": 48
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "user_id": "user_123",
    "blocked": true,
    "expires_at": "2026-11-15T10:00:00Z"
  }
  ```

---

## 5. Bot Management (`/kep/bot`)

### `POST /kep/bot/heartbeat`
Bot health and load reporting.
- **Auth**: Required
- **Request Body**:
  ```json
  {
    "status": "idle",
    "load": 0.25
  }
  ```
- **Response `200 OK`**:
  ```json
  {
    "status": "alive",
    "acknowledged": true
  }
  ```

### `GET /kep/bot/config/:bot_id`
Retrieves limits and enabled capabilities for the bot.
- **Auth**: Required
- **Response `200 OK`**:
  ```json
  {
    "bot_id": "anime_girl",
    "max_tokens_per_request": 2000,
    "enabled_features": ["chat", "voice", "vision"]
  }
  ```

---

## Standard Error Format

All errors return JSON envelopes:
```json
{
  "error": {
    "code": "UNAUTHORIZED",
    "message": "signature expired"
  }
}
```
StatusCodes: `400 BAD_REQUEST`, `401 UNAUTHORIZED`, `403 FORBIDDEN`, `404 NOT_FOUND`, `409 CONFLICT`, `500 INTERNAL_ERROR`.
