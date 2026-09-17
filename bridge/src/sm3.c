#include "sm3.h"

#include <string.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

static uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | (x & z) | (y & z);
}

static uint32_t gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j < 16) return x ^ y ^ z;
    return (x & y) | ((~x) & z);
}

void sm3_init(SM3_CTX *ctx) {
    ctx->state[0] = 0x7380166f;
    ctx->state[1] = 0x4914b2b9;
    ctx->state[2] = 0x172442d7;
    ctx->state[3] = 0xda8a0600;
    ctx->state[4] = 0xa96f30bc;
    ctx->state[5] = 0x163138aa;
    ctx->state[6] = 0xe38dee4d;
    ctx->state[7] = 0xb0fb0e4e;
    ctx->total_len = 0;
    ctx->buf_len = 0;
}

static void sm3_compress(SM3_CTX *ctx, const uint8_t block[64]) {
    uint32_t w[68];
    uint32_t wp[64];
    int j;

    for (j = 0; j < 16; j++) w[j] = load_be32(block + j * 4);
    for (j = 16; j < 68; j++)
        w[j] = P1(w[j - 16] ^ w[j - 9] ^ ROTL(w[j - 3], 15)) ^
               ROTL(w[j - 13], 7) ^ w[j - 6];
    for (j = 0; j < 64; j++) wp[j] = w[j] ^ w[j + 4];

    uint32_t a = ctx->state[0], b = ctx->state[1];
    uint32_t c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5];
    uint32_t g = ctx->state[6], h = ctx->state[7];

    for (j = 0; j < 64; j++) {
        uint32_t tj = (j < 16) ? 0x79cc4519u : 0x7a879d8au;
        uint32_t ss1 = ROTL((ROTL(a, 12) + e + ROTL(tj, j % 32)) & 0xffffffffu, 7);
        uint32_t ss2 = ss1 ^ ROTL(a, 12);
        uint32_t tt1 = (ff(a, b, c, j) + d + ss2 + wp[j]) & 0xffffffffu;
        uint32_t tt2 = (gg(e, f, g, j) + h + ss1 + w[j]) & 0xffffffffu;

        d = c; c = ROTL(b, 9); b = a; a = tt1;
        h = g; g = ROTL(f, 19); f = e; e = P0(tt2);
    }

    ctx->state[0] ^= a; ctx->state[1] ^= b;
    ctx->state[2] ^= c; ctx->state[3] ^= d;
    ctx->state[4] ^= e; ctx->state[5] ^= f;
    ctx->state[6] ^= g; ctx->state[7] ^= h;
}

void sm3_update(SM3_CTX *ctx, const uint8_t *data, size_t len) {
    ctx->total_len += len;
    while (len > 0) {
        size_t take = 64 - ctx->buf_len;
        if (take > len) take = len;
        memcpy(ctx->buffer + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == 64) {
            sm3_compress(ctx, ctx->buffer);
            ctx->buf_len = 0;
        }
    }
}

void sm3_final(SM3_CTX *ctx, uint8_t out[32]) {
    uint64_t bitlen = (uint64_t)ctx->total_len * 8;
    uint8_t pad[72];
    size_t padlen = (ctx->buf_len < 56) ? (56 - ctx->buf_len) : (120 - ctx->buf_len);
    uint8_t lb[8];
    int i;

    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    sm3_update(ctx, pad, padlen);

    for (i = 0; i < 8; i++) lb[i] = (uint8_t)(bitlen >> (56 - 8 * i));
    sm3_update(ctx, lb, 8);

    for (i = 0; i < 8; i++) store_be32(out + i * 4, ctx->state[i]);
}
