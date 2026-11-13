#ifndef KEP_SHA256_H
#define KEP_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define KEP_SHA256_BLOCK_SIZE 64
#define KEP_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[KEP_SHA256_BLOCK_SIZE];
} kep_sha256_ctx;

void kep_sha256_init(kep_sha256_ctx *ctx);
void kep_sha256_update(kep_sha256_ctx *ctx, const uint8_t *data, size_t len);
void kep_sha256_final(kep_sha256_ctx *ctx, uint8_t out[KEP_SHA256_DIGEST_SIZE]);
void kep_sha256(const uint8_t *data, size_t len, uint8_t out[KEP_SHA256_DIGEST_SIZE]);

#endif
