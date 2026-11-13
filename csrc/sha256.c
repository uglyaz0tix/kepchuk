#include "sha256.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static inline uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static inline uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

static inline uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static void transform(kep_sha256_ctx *ctx, const uint8_t block[KEP_SHA256_BLOCK_SIZE]) {
    uint32_t w[64];
    for (size_t i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    for (size_t i = 16; i < 64; i++) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];

    for (size_t i = 0; i < 64; i++) {
        uint32_t t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void kep_sha256_init(kep_sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void kep_sha256_update(kep_sha256_ctx *ctx, const uint8_t *data, size_t len) {
    // buffer incoming bytes and process full 64-byte blocks
    size_t buffer_fill = (size_t)(ctx->count % KEP_SHA256_BLOCK_SIZE);
    ctx->count += (uint64_t)len;

    if (buffer_fill > 0) {
        size_t needed = KEP_SHA256_BLOCK_SIZE - buffer_fill;
        if (len < needed) {
            memcpy(ctx->buffer + buffer_fill, data, len);
            return;
        }
        memcpy(ctx->buffer + buffer_fill, data, needed);
        transform(ctx, ctx->buffer);
        data += needed;
        len -= needed;
    }

    while (len >= KEP_SHA256_BLOCK_SIZE) {
        transform(ctx, data);
        data += KEP_SHA256_BLOCK_SIZE;
        len -= KEP_SHA256_BLOCK_SIZE;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

void kep_sha256_final(kep_sha256_ctx *ctx, uint8_t out[KEP_SHA256_DIGEST_SIZE]) {
    // pad with 0x80 followed by zeros and 64-bit length in bits
    uint64_t total_bits = ctx->count * 8;
    size_t buffer_fill = (size_t)(ctx->count % KEP_SHA256_BLOCK_SIZE);

    ctx->buffer[buffer_fill++] = 0x80;
    if (buffer_fill > 56) {
        memset(ctx->buffer + buffer_fill, 0, KEP_SHA256_BLOCK_SIZE - buffer_fill);
        transform(ctx, ctx->buffer);
        buffer_fill = 0;
    }
    memset(ctx->buffer + buffer_fill, 0, 56 - buffer_fill);

    for (int i = 7; i >= 0; i--) {
        ctx->buffer[56 + (7 - i)] = (uint8_t)((total_bits >> (i * 8)) & 0xff);
    }
    transform(ctx, ctx->buffer);

    for (size_t i = 0; i < 8; i++) {
        out[i * 4] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
        out[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        out[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        out[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xff);
    }
}

void kep_sha256(const uint8_t *data, size_t len, uint8_t out[KEP_SHA256_DIGEST_SIZE]) {
    kep_sha256_ctx ctx;
    kep_sha256_init(&ctx);
    kep_sha256_update(&ctx, data, len);
    kep_sha256_final(&ctx, out);
}
