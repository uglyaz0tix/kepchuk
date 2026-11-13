# Bot Developer Guide: Connecting in 15 Minutes

This guide walks you through registering a bot, signing requests with HMAC-SHA256, and consuming user tokens.

---

## 1. Step 1: Register Your Bot

Send a one-time registration request:

```bash
curl -X POST http://localhost:8080/kep/auth/register \
  -H "Content-Type: application/json" \
  -d '{"bot_id": "yuki_chan"}'
```

Response:
```json
{
  "bot_id": "yuki_chan",
  "api_key": "ak_live_...",
  "bot_secret": "sec_..."
}
```

Store `api_key` and `bot_secret` securely in your bot's environment variables.

---

## 2. Signature Algorithm

Every request to protected endpoints must carry:
1. `X-Bot-ID`: `bot_id`
2. `X-API-Key`: `api_key`
3. `X-Timestamp`: current unix timestamp (in seconds)
4. `X-Nonce`: unique UUID v4 or random hex string (replayed nonces within 5 min return 409)
5. `X-Signature`: hex HMAC-SHA256 signature calculated over:

```text
time_window = timestamp / 300
body_sha256 = hex(sha256(request_body))
message = bot_id + ":" + timestamp + ":" + nonce + ":" + body_sha256
signature = hex(hmac_sha256(bot_secret, time_window + ":" + message))
```

---

## 3. Python Implementation

```python
import time
import uuid
import hashlib
import hmac
import json
import urllib.request

BOT_ID = "yuki_chan"
API_KEY = "ak_live_..."
BOT_SECRET = "sec_..."
BASE_URL = "http://localhost:8080"

def send_signed_request(endpoint: str, payload: dict = None):
    url = f"{BASE_URL}{endpoint}"
    body_bytes = json.dumps(payload).encode("utf-8") if payload else b""
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    
    timestamp = int(time.time())
    nonce = str(uuid.uuid4())
    time_window = str(timestamp // 300)
    
    message = f"{BOT_ID}:{timestamp}:{nonce}:{body_hash}"
    signed_payload = f"{time_window}:{message}".encode("utf-8")
    signature = hmac.new(BOT_SECRET.encode("utf-8"), signed_payload, hashlib.sha256).hexdigest()
    
    headers = {
        "Content-Type": "application/json",
        "X-Bot-ID": BOT_ID,
        "X-API-Key": API_KEY,
        "X-Timestamp": str(timestamp),
        "X-Nonce": nonce,
        "X-Signature": signature,
    }
    
    req = urllib.request.Request(url, data=body_bytes if payload else None, headers=headers)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode("utf-8"))

# Check balance
status = send_signed_request("/kep/subs/status/user_999")
print("User balance:", status["tokens"])

# Consume tokens for response
result = send_signed_request("/kep/subs/consume", {
    "user_id": "user_999",
    "tokens": 20,
    "reason": "chat_reply"
})
print("Remaining balance:", result["new_balance"])
```

---

## 4. Go Implementation

```go
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type Client struct {
	BaseURL   string
	BotID     string
	APIKey    string
	BotSecret string
	HTTP      *http.Client
}

func (c *Client) ConsumeTokens(userID string, tokens int64, reason string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"user_id": userID,
		"tokens":  tokens,
		"reason":  reason,
	})

	bodyHashBytes := sha256.Sum256(payload)
	bodyHash := hex.EncodeToString(bodyHashBytes[:])

	now := time.Now().Unix()
	nonce := uuid.New().String()
	timeWindow := strconv.FormatInt(now/300, 10)

	msg := fmt.Sprintf("%s:%d:%s:%s", c.BotID, now, nonce, bodyHash)
	signedData := fmt.Sprintf("%s:%s", timeWindow, msg)

	mac := hmac.New(sha256.New, []byte(c.BotSecret))
	mac.Write([]byte(signedData))
	sig := hex.EncodeToString(mac.Sum(nil))

	req, _ := http.NewRequest("POST", c.BaseURL+"/kep/subs/consume", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bot-ID", c.BotID)
	req.Header.Set("X-API-Key", c.APIKey)
	req.Header.Set("X-Timestamp", strconv.FormatInt(now, 10))
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Signature", sig)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed with status: %d", resp.StatusCode)
	}
	return nil
}
```
