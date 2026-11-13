#include "secure_compare.h"

int kep_secure_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    // constant-time comparison without branch shortcuts
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0 ? 1 : 0;
}
