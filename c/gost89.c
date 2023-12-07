#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "gost89.h"

void gost89_expand_sbox(uint8_t (*sbox)[16], uint8_t (*sbox_x)[256]) {
    int i, j, k;

    for (i = 0; i < 256; i++) {
        j = i / 16;
        k = i % 16;
        sbox_x[0][i] = sbox[1][j] << 4 | sbox[0][k];
        sbox_x[1][i] = sbox[3][j] << 4 | sbox[2][k];
        sbox_x[2][i] = sbox[5][j] << 4 | sbox[4][k];
        sbox_x[3][i] = sbox[7][j] << 4 | sbox[6][k];
    }
}

void gost89_set_sbox(gost89_context *ctx, uint8_t (*sbox)[16]) {
    memcpy(ctx->sbox, sbox, sizeof(ctx->sbox));
    gost89_expand_sbox(ctx->sbox, ctx->sbox_x);
}

void gost89_set_key(gost89_context *ctx, void *key) {
    memcpy(ctx->key, key, sizeof(ctx->key));
}

void gost89_set_iv(gost89_context *ctx, void *iv) {
    if (iv != NULL) {
        memcpy(ctx->iv, iv, sizeof(ctx->iv));
    } else {
        ctx->iv[0] = 0;
        ctx->iv[1] = 0;
    }
}

void gost89_set_mac(gost89_context *ctx, void *mac) {
    if (mac != NULL) {
        memcpy(ctx->mac, mac, sizeof(ctx->mac));
    } else {
        ctx->mac[0] = 0;
        ctx->mac[1] = 0;
    }
}

#define gost89_round_0(block, key) (            \
    t = block + key,                            \
    t = ctx->sbox[0][t & 0xF] |                 \
        ctx->sbox[1][t >> 4 & 0xF] << 4 |       \
        ctx->sbox[2][t >> 8 & 0xF] << 8 |       \
        ctx->sbox[3][t >> 12 & 0xF] << 12 |     \
        ctx->sbox[4][t >> 16 & 0xF] << 16 |     \
        ctx->sbox[5][t >> 20 & 0xF] << 20 |     \
        ctx->sbox[6][t >> 24 & 0xF] << 24 |     \
        ctx->sbox[7][t >> 28 & 0xF] << 28,      \
    t << 11 | t >> 21                           \
)

#define gost89_round_1(block, key) (            \
    t = block + key,                            \
    t = ctx->sbox_x[0][t & 0xFF] |              \
        ctx->sbox_x[1][t >> 8 & 0xFF] << 8 |    \
        ctx->sbox_x[2][t >> 16 & 0xFF] << 16 |  \
        ctx->sbox_x[3][t >> 24 & 0xFF] << 24,   \
    t << 11 | t >> 21                           \
)

#define gost89_round gost89_round_1

void gost89_encrypt(gost89_context *ctx, void *plain, void *encrypted) {
    int i;
    uint32_t t;
    uint32_t a = ((uint32_t*)plain)[0];
    uint32_t b = ((uint32_t*)plain)[1];
    uint32_t *k = ctx->key;

    for (i = 0; i < 3; i++) {
        b ^= gost89_round(a, k[0]);
        a ^= gost89_round(b, k[1]);
        b ^= gost89_round(a, k[2]);
        a ^= gost89_round(b, k[3]);
        b ^= gost89_round(a, k[4]);
        a ^= gost89_round(b, k[5]);
        b ^= gost89_round(a, k[6]);
        a ^= gost89_round(b, k[7]);
    }

    b ^= gost89_round(a, k[7]);
    a ^= gost89_round(b, k[6]);
    b ^= gost89_round(a, k[5]);
    a ^= gost89_round(b, k[4]);
    b ^= gost89_round(a, k[3]);
    a ^= gost89_round(b, k[2]);
    b ^= gost89_round(a, k[1]);
    a ^= gost89_round(b, k[0]);

    ((uint32_t*)encrypted)[0] = b;
    ((uint32_t*)encrypted)[1] = a;
}

void gost89_decrypt(gost89_context *ctx, void *encrypted, void *plain) {
    int i;
    uint32_t t;
    uint32_t a = ((uint32_t*)encrypted)[0];
    uint32_t b = ((uint32_t*)encrypted)[1];
    uint32_t *k = ctx->key;

    b ^= gost89_round(a, k[0]);
    a ^= gost89_round(b, k[1]);
    b ^= gost89_round(a, k[2]);
    a ^= gost89_round(b, k[3]);
    b ^= gost89_round(a, k[4]);
    a ^= gost89_round(b, k[5]);
    b ^= gost89_round(a, k[6]);
    a ^= gost89_round(b, k[7]);

    for (i = 0; i < 3; i++) {
        b ^= gost89_round(a, k[7]);
        a ^= gost89_round(b, k[6]);
        b ^= gost89_round(a, k[5]);
        a ^= gost89_round(b, k[4]);
        b ^= gost89_round(a, k[3]);
        a ^= gost89_round(b, k[2]);
        b ^= gost89_round(a, k[1]);
        a ^= gost89_round(b, k[0]);
    }

    ((uint32_t*)plain)[0] = b;
    ((uint32_t*)plain)[1] = a;
}

void gost89_encrypt_16(gost89_context *ctx, void *plain, void *encrypted) {
    int i;
    uint32_t t;
    uint32_t a = ((uint32_t*)plain)[0];
    uint32_t b = ((uint32_t*)plain)[1];
    uint32_t *k = ctx->key;

    for (i = 0; i < 2; i++) {
        b ^= gost89_round(a, k[0]);
        a ^= gost89_round(b, k[1]);
        b ^= gost89_round(a, k[2]);
        a ^= gost89_round(b, k[3]);
        b ^= gost89_round(a, k[4]);
        a ^= gost89_round(b, k[5]);
        b ^= gost89_round(a, k[6]);
        a ^= gost89_round(b, k[7]);
    }

    ((uint32_t*)encrypted)[0] = a;
    ((uint32_t*)encrypted)[1] = b;
}

void gost89_decrypt_16(gost89_context *ctx, void *encrypted, void *plain) {
    int i;
    uint32_t t;
    uint32_t a = ((uint32_t*)encrypted)[0];
    uint32_t b = ((uint32_t*)encrypted)[1];
    uint32_t *k = ctx->key;

    for (i = 0; i < 2; i++) {
        a ^= gost89_round(b, k[7]);
        b ^= gost89_round(a, k[6]);
        a ^= gost89_round(b, k[5]);
        b ^= gost89_round(a, k[4]);
        a ^= gost89_round(b, k[3]);
        b ^= gost89_round(a, k[2]);
        a ^= gost89_round(b, k[1]);
        b ^= gost89_round(a, k[0]);
    }

    ((uint32_t*)plain)[0] = a;
    ((uint32_t*)plain)[1] = b;
}

void gost89_encrypt_ecb(gost89_context *ctx, void *plain, void *encrypted, unsigned size) {
    unsigned i, l = size / sizeof(uint32_t);

    for (i = 0; i < l; i += 2) {
        gost89_encrypt(ctx, (uint32_t*)plain + i, (uint32_t*)encrypted + i);
    }
}

void gost89_decrypt_ecb(gost89_context *ctx, void *encrypted, void *plain, unsigned size) {
    unsigned i, l = size / sizeof(uint32_t);

    for (i = 0; i < l; i += 2) {
        gost89_decrypt(ctx, (uint32_t*)encrypted + i, (uint32_t*)plain + i);
    }
}

void gost89_init_ctr(gost89_context *ctx) {
    gost89_encrypt(ctx, ctx->iv, ctx->iv);
}

void gost89_encrypt_ctr(gost89_context *ctx, void *plain, void *encrypted, unsigned size) {
    unsigned i, l = size / sizeof(uint32_t);
    uint32_t t[2];

    for (i = 0; i < l; i += 2) {
        ctx->iv[0] += 0x1010101;

        if (ctx->iv[1] > 0xFFFFFFFF - 0x1010104) {
            ctx->iv[1] += 0x1010104 + 1;
        } else {
            ctx->iv[1] += 0x1010104;
        }

        gost89_encrypt(ctx, ctx->iv, t);

        ((uint32_t*)encrypted)[i] = ((uint32_t*)plain)[i] ^ t[0];
        ((uint32_t*)encrypted)[i + 1] = ((uint32_t*)plain)[i + 1] ^ t[1];
    }
}

void gost89_encrypt_cfb(gost89_context *ctx, void *plain, void *encrypted, unsigned size) {
    unsigned i, l = size / sizeof(uint32_t);

    for (i = 0; i < l; i += 2) {
        gost89_encrypt(ctx, ctx->iv, ctx->iv);

        ((uint32_t*)encrypted)[i] = ((uint32_t*)plain)[i] ^ ctx->iv[0];
        ((uint32_t*)encrypted)[i + 1] = ((uint32_t*)plain)[i + 1] ^ ctx->iv[1];

        ctx->iv[0] = ((uint32_t*)encrypted)[i];
        ctx->iv[1] = ((uint32_t*)encrypted)[i + 1];
    }
}

void gost89_decrypt_cfb(gost89_context *ctx, void *encrypted, void *plain, unsigned size) {
    unsigned i, l = size / sizeof(uint32_t);
    uint32_t a;
    uint32_t b;

    for (i = 0; i < l; i += 2) {
        a = ((uint32_t*)encrypted)[i];
        b = ((uint32_t*)encrypted)[i + 1];

        gost89_encrypt(ctx, ctx->iv, ctx->iv);

        ((uint32_t*)plain)[i] = a ^ ctx->iv[0];
        ((uint32_t*)plain)[i + 1] = b ^ ctx->iv[1];

        ctx->iv[0] = a;
        ctx->iv[1] = b;
    }
}

void gost89_mac(gost89_context *ctx, void *plain, unsigned size) {
    unsigned i, l = size / sizeof(uint32_t);
    uint32_t t[2];

    t[0] = ctx->mac[0];
    t[1] = ctx->mac[1];

    for (i = 0; i < l; i += 2) {
        t[0] ^= ((uint32_t*)plain)[i];
        t[1] ^= ((uint32_t*)plain)[i + 1];

        gost89_encrypt_16(ctx, t, t);
    }

    ctx->mac[0] = t[0];
    ctx->mac[1] = t[1];
}
