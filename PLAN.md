# Implementation Plan: KepchukAPI

## Architecture & Design Guidelines
- Pure C11 cryptographic layer (`csrc/`): zero external crypto dependencies (no OpenSSL, ring, or libsodium).
- Standard FIPS 180-4 SHA-256, RFC 2104 / RFC 4231 HMAC-SHA256, and constant-time memory comparison in C.
- Safe Rust FFI bridge built with `cc` and `bindgen`, exposing ergonomic safe APIs.
- Modular axum HTTP service with layered authentication (API Key, HMAC-SHA256 with 300s TTL window, Nonce replay prevention).
- Pluggable storage abstraction (`Storage` trait) supporting both in-memory (testing) and SQLite (persistence).
- Cross-platform support (Windows, Linux, macOS) targeting x86_64 and ARM64.
- Minimal comments (strictly lowercase), all code and documentation in English.

---

## Phase 1: Cryptographic Foundation (C + FFI)
- [ ] Implement pure C11 SHA-256 in `csrc/sha256.h` and `csrc/sha256.c` (FIPS 180-4 compliance, handling arbitrary message lengths).
- [ ] Implement HMAC-SHA256 in `csrc/hmac.h` and `csrc/hmac.c` (RFC 2104 / RFC 4231 compliant).
- [ ] Implement constant-time comparison in `csrc/secure_compare.h` and `csrc/secure_compare.c`.
- [ ] Create unified header `csrc/kep_crypto.h` for bindgen.
- [ ] Configure `Cargo.toml` with `cc` and `bindgen` (build dependencies) and runtime crates (`subtle`, `hex`).
- [ ] Implement `build.rs` compiling `csrc` into static library `libkep_crypto.a` and generating bindings.
- [ ] Implement safe Rust wrapper in `src/crypto/mod.rs` and `src/crypto/wrapper.rs`.
- [ ] Add RFC 4231 test suite in `tests/crypto_vectors.rs`.
- [ ] Verify `cargo test --test crypto_vectors` passes 100%.

## Phase 2: HTTP Server Foundation
- [ ] Setup `Cargo.toml` dependencies: `axum`, `tokio`, `tower`, `tower-http`, `serde`, `serde_json`, `tracing`, `tracing-subscriber`.
- [ ] Implement environment-based configuration in `src/config.rs` (`KEPCHUK_PORT`, `KEPCHUK_HOST`, `KEPCHUK_DB_URL`, etc.).
- [ ] Implement structured error handling in `src/domain/errors.rs`.
- [ ] Build basic router with `/healthz` and `/readyz` endpoints in `src/api/router.rs`.
- [ ] Implement `src/main.rs` with tokio runtime, graceful shutdown (Ctrl+C / SIGTERM), and tracing subscriber.
- [ ] Verify server startup and health check response.

## Phase 3: Authentication & Security Middleware
- [ ] Implement in-memory DashMap nonce store with TTL expiration in `src/nonce/mod.rs` and `src/nonce/memory.rs`.
- [ ] Define authentication middleware in `src/api/middleware.rs`:
  - Level 1: `X-Bot-ID` and `X-API-Key` validation against storage.
  - Level 2: `X-Timestamp` TTL validation (`|now - ts| <= 300`) and HMAC-SHA256 signature verification over canonical payload.
  - Level 3: `X-Nonce` validation and single-use reservation (reject duplicates with 409 Conflict).
- [ ] Implement unit and integration tests for auth middleware: missing headers, expired timestamps, invalid signatures, nonce replay.

## Phase 4: Domain & Storage Abstraction
- [ ] Define core domain models in `src/domain/`: `bot.rs`, `user.rs`, `billing.rs`.
- [ ] Create `Storage` trait in `src/storage/mod.rs` for bot lookup, user balance querying, atomic token consumption, blocking, and ledger logging.
- [ ] Implement `MemoryStorage` in `src/storage/memory.rs` for fast integration testing.
- [ ] Implement `SqliteStorage` in `src/storage/sqlite.rs` with connection pooling (`rusqlite` with bundled SQLite).
- [ ] Add schema migration `migrations/001_init.sql` for bots, users, transactions, and blocks.
- [ ] Test billing operations (atomic debit, insufficient balance check, idempotent processing).

## Phase 5: API Endpoints
- [ ] Auth endpoints (`/kep/auth/`):
  - `POST /kep/auth/register` - bot registration, returning `bot_id`, raw `api_key`, and `bot_secret`.
  - `POST /kep/auth/rotate` - secret rotation using existing API key.
- [ ] Subscription & Billing endpoints (`/kep/subs/`):
  - `GET /kep/subs/status/:user_id` - retrieve user balance and tier.
  - `POST /kep/subs/consume` - atomic token debit with reason.
  - `POST /kep/subs/purchase` - payment webhook processing.
- [ ] Blocking endpoints (`/kep/block/`):
  - `GET /kep/block/check/:user_id` - check user block status.
  - `POST /kep/block/user` - apply timed or permanent user block.
- [ ] Bot endpoints (`/kep/bot/`):
  - `POST /kep/bot/heartbeat` - bot heartbeat report.
  - `GET /kep/bot/config/:bot_id` - dynamic bot configuration retrieval.
- [ ] Standardized error response format `{"error": {"code": "...", "message": "..."}}`.
- [ ] Write comprehensive end-to-end integration tests in `tests/integration_test.rs`.

## Phase 6: Documentation & Guides
- [ ] Write `docs/API.md` with complete endpoint descriptions, headers, request/response bodies, and status codes.
- [ ] Write `docs/BOT_GUIDE.md` providing step-by-step instructions for bot developers (with curl, Python, and Go examples).
- [ ] Write `SECURITY.md` explaining threat model, constant-time validation, and build verification.
- [ ] Write `README.md` with philosophy, 5-line quickstart, and architecture overview.
- [ ] Add `LICENSE` (BSD-3-Clause).

## Phase 7: Packaging, CI & Release
- [ ] Configure GitHub Actions workflow in `.github/workflows/ci.yml` (multi-platform matrix: Linux x86_64, Linux ARM64, macOS, Windows).
- [ ] Run `cargo clippy -- -D warnings` and `cargo fmt --check`.
- [ ] Run full test suite: unit tests, RFC 4231 vectors, integration tests.
- [ ] Initialize git repository, configure remote, and push to GitHub using `gh repo create`.
