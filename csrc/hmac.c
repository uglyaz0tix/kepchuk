#include "hmac.h"
#include <string.h>

void kep_hmac_sha256_init(kep_hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len) {
    uint8_t k_block[KEP_SHA256_BLOCK_SIZE];
    uint8_t k_pad[KEP_SHA256_BLOCK_SIZE];

    memset(k_block, 0, sizeof(k_block));
    if (key_len > KEP_SHA256_BLOCK_SIZE) {
        kep_sha256(key, key_len, k_block);
    } else {
        memcpy(k_block, key, key_len);
    }

    // inner ipad 0x36
    for (size_t i = 0; i < KEP_SHA256_BLOCK_SIZE; i++) {
        k_pad[i] = k_block[i] ^ 0x36;
    }
    kep_sha256_init(&ctx->inner);
    kep_sha256_update(&ctx->inner, k_pad, KEP_SHA256_BLOCK_SIZE);

    // outer opad 0x5c
    for (size_t i = 0; i < KEP_SHA256_BLOCK_SIZE; i++) {
        k_pad[i] = k_block[i] ^ 0x5c;
    }
    kep_sha256_init(&ctx->outer);
    kep_sha256_update(&ctx->outer, k_pad, KEP_SHA256_BLOCK_SIZE);
}

void kep_hmac_sha256_update(kep_hmac_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    kep_sha256_update(&ctx->inner, data, len);
}

void kep_hmac_sha256_final(kep_hmac_sha256_ctx *ctx, uint8_t out[KEP_HMAC_SHA256_DIGEST_SIZE]) {
    uint8_t inner_digest[KEP_SHA256_DIGEST_SIZE];
    kep_sha256_final(&ctx->inner, inner_digest);
    kep_sha256_update(&ctx->outer, inner_digest, sizeof(inner_digest));
    kep_sha256_final(&ctx->outer, out);
}

void kep_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t out[KEP_HMAC_SHA256_DIGEST_SIZE]) {
    kep_hmac_sha256_ctx ctx;
    kep_hmac_sha256_init(&ctx, key, key_len);
    kep_hmac_sha256_update(&ctx, data, len);
    kep_hmac_sha256_final(&ctx, out);
}
