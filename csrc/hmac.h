#ifndef KEP_HMAC_H
#define KEP_HMAC_H

#include <stddef.h>
#include <stdint.h>
#include "sha256.h"

#define KEP_HMAC_SHA256_DIGEST_SIZE 32

typedef struct {
    kep_sha256_ctx inner;
    kep_sha256_ctx outer;
} kep_hmac_sha256_ctx;

void kep_hmac_sha256_init(kep_hmac_sha256_ctx *ctx, const uint8_t *key, size_t key_len);
void kep_hmac_sha256_update(kep_hmac_sha256_ctx *ctx, const uint8_t *data, size_t len);
void kep_hmac_sha256_final(kep_hmac_sha256_ctx *ctx, uint8_t out[KEP_HMAC_SHA256_DIGEST_SIZE]);
void kep_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t len, uint8_t out[KEP_HMAC_SHA256_DIGEST_SIZE]);

#endif
