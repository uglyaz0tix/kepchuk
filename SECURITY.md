# Security Policy & Threat Model

KepchukAPI follows a strict zero-external-crypto manifest designed to minimize attack surface and supply chain risks.

## Core Security Architecture

1. **Pure C Cryptography**:
   - SHA-256 and HMAC-SHA256 implemented in audited C11 (`csrc/`).
   - Zero dynamic links to OpenSSL, libssl, ring, or third-party crypto crates.
   - Verified against NIST FIPS 180-4 and RFC 4231 test vectors on every build.

2. **Constant-Time Verification**:
   - Signature comparisons never use standard `==` or short-circuiting comparisons.
   - Verification combines a C volatile accumulator (`csrc/secure_compare.c`) and Rust's `subtle::ConstantTimeEq` to eliminate timing attacks.

3. **Three-Layer Authorization**:
   - **Level 1 (Identity)**: `X-Bot-ID` + `X-API-Key`. Raw API keys are never stored in plaintext; only SHA-256 digests reside in the database.
   - **Level 2 (Proof of Possession & TTL)**: `X-Timestamp` and `X-Signature`. Timestamps are restricted to a sliding 300-second window (`|now - ts| <= 300`).
   - **Level 3 (Replay Protection)**: `X-Nonce`. Every request nonce is recorded in an in-memory TTL store. Replay attempts within the validity window are rejected with `409 Conflict`.

4. **Safe FFI Boundary**:
   - Unsafe C calls are strictly contained inside `src/crypto/wrapper.rs`.
   - The public Rust interface exposes only safe, strongly-typed functions with automatic memory boundaries.

5. **Cross-Platform Static Compilation**:
   - C code compiles directly into the target binary using the system compiler (`gcc`, `clang`, or `msvc`).
   - SQLite is statically embedded with the `bundled` feature, removing external runtime shared library dependencies.

## Reporting a Vulnerability

If you discover a security vulnerability, please open a private GitHub Security Advisory or report it directly via GitHub issues.
