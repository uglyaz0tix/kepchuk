# KepchukAPI

[![CI](https://github.com/uglyaz0tix/kepchuk/actions/workflows/ci.yml/badge.svg)](https://github.com/uglyaz0tix/kepchuk/actions)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](LICENSE)
[![Rust 1.75+](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org)
[![C11](https://img.shields.io/badge/C-C11-00599C.svg)](csrc/)

KepchukAPI is a high-performance **Central Server (CS)** for AI character networks. Bots communicate with end users across messengers, consume tokens, and rely on KepchukAPI for atomic balance management, rate limits, and cryptographic security.

---

## ⚡ 5-Line Quickstart

```bash
git clone https://github.com/uglyaz0tix/kepchuk.git
cd kepchuk
cargo run --release
# In another terminal:
curl http://localhost:8080/healthz
```

---

## 🏛️ Manifest & Architecture Principles

1. **Zero External Crypto Crates**: SHA-256 and HMAC-SHA256 are written in pure C11. No OpenSSL, ring, or libsodium.
2. **Transparent Security**: Constant-time byte comparisons across C and Rust to prevent side-channel timing attacks.
3. **Rust for Safety & Concurrency**: Network handling, routing, and concurrency run on Axum and Tokio.
4. **Clean FFI Integration**: The C crypto engine is compiled into static library `libkep_crypto.a` via `build.rs` and bound with `bindgen`.
5. **Cross-Platform**: Tested on Linux (`x86_64`, `aarch64`), Windows (`x86_64`), and macOS (`arm64`, `x86_64`).

```text
┌─────────────────────────────────────────────────────┐
│ KepchukAPI (Rust / axum)                            │
│  ┌──────────────┐   ┌──────────────┐  ┌───────────┐ │
│  │ HTTP Server  │   │ Nonce Cache  │  │ Webhooks  │ │
│  └──────┬───────┘   └──────┬───────┘  └─────┬─────┘ │
│         │                  │                │       │
│         └──────────────────┼────────────────┘       │
│                            ▼                        │
│                 ┌────────────────────────┐          │
│                 │ Core Billing Engine    │          │
│                 │ - SQLite/Memory Store  │          │
│                 │ - 3-Layer Auth Filter  │          │
│                 └───────────┬────────────┘          │
│                             │ FFI                   │
│                 ┌───────────▼────────────┐          │
│                 │ Pure C11 Crypto Engine │          │
│                 │ - SHA-256 (FIPS 180-4) │          │
│                 │ - HMAC (RFC 4231)      │          │
│                 │ - Constant-Time Cmp    │          │
│                 └────────────────────────┘          │
└─────────────────────────────────────────────────────┘
```

---

## 🔐 3-Layer Authentication

Every protected bot request validates 3 layers:
- **Level 1 (Identity)**: `X-Bot-ID` + `X-API-Key` (SHA-256 hashed in database).
- **Level 2 (Signature & TTL)**: `X-Timestamp` (within 300s window) + `X-Signature` (HMAC-SHA256 over time window, nonce, and body hash).
- **Level 3 (Replay Protection)**: `X-Nonce` (UUID or hex, cached in DashMap for 5 minutes).

Formula:
```text
time_window = timestamp / 300
body_hash = sha256_hex(body)
message = bot_id + ":" + timestamp + ":" + nonce + ":" + body_hash
signature = HMAC_SHA256(bot_secret, time_window + ":" + message)
```

---

## 🧪 Testing & Verification

Run the full Rust test suite (including RFC 4231 test vectors):
```bash
cargo test
```

Run the automated Python security verification suite against a live server:
```bash
python tests/security_check.py http://127.0.0.1:8080
```

---

## 📚 Documentation

- [Interactive HTML Documentation](docs/index.html) — standalone visual API reference and bot integration guide.
- [API Reference](docs/API.md) — complete endpoint specifications and request/response models.
- [Bot Developer Guide](docs/BOT_GUIDE.md) — 15-minute quickstart for Python and Go bot authors.
- [Security Policy](SECURITY.md) — threat analysis and cryptographic guarantees.

---

## 📄 License

[BSD 3-Clause License](LICENSE)
