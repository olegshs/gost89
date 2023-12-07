#ifndef GOST89_H_
#define GOST89_H_

#include <stdint.h>

typedef struct gost89_context {
    uint8_t sbox[8][16];
    uint8_t sbox_x[4][256];
    uint32_t key[8];
    uint32_t iv[2];
    uint32_t mac[2];
} gost89_context;

#ifdef __cplusplus
extern "C" {
#endif

extern void gost89_expand_sbox(uint8_t (*sbox)[16], uint8_t (*sbox_x)[256]);
extern void gost89_set_sbox(gost89_context *ctx, uint8_t (*sbox)[16]);
extern void gost89_set_key(gost89_context *ctx, void *key);
extern void gost89_set_iv(gost89_context *ctx, void *iv);
extern void gost89_set_mac(gost89_context *ctx, void *mac);
extern void gost89_encrypt(gost89_context *ctx, void *plain, void *encrypted);
extern void gost89_decrypt(gost89_context *ctx, void *encrypted, void *plain);
extern void gost89_encrypt_ecb(gost89_context *ctx, void *plain, void *encrypted, unsigned size);
extern void gost89_decrypt_ecb(gost89_context *ctx, void *encrypted, void *plain, unsigned size);
extern void gost89_init_ctr(gost89_context *ctx);
extern void gost89_encrypt_ctr(gost89_context *ctx, void *plain, void *encrypted, unsigned size);
extern void gost89_encrypt_cfb(gost89_context *ctx, void *plain, void *encrypted, unsigned size);
extern void gost89_decrypt_cfb(gost89_context *ctx, void *encrypted, void *plain, unsigned size);
extern void gost89_mac(gost89_context *ctx, void *plain, unsigned size);

#ifdef __cplusplus
}
#endif

#endif /* GOST89_H_ */
