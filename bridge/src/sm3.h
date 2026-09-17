#ifndef CC_BRIDGE_SM3_H
#define CC_BRIDGE_SM3_H

#include <stddef.h>
#include <stdint.h>

/*
 * Bootstrap reference SM3 (GM/T 0004-2012).
 * This is a placeholder so the bridge can compile & be validated by CI.
 * The real implementation MUST call openHiTLS (libhitls_crypto).
 */
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t total_len;
    uint8_t buffer[64];
    size_t buf_len;
} SM3_CTX;

void sm3_init(SM3_CTX *ctx);
void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len);
void sm3_final(SM3_CTX *ctx, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif /* CC_BRIDGE_SM3_H */
