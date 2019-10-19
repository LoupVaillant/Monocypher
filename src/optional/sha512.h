// Monocypher version __git__

#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <inttypes.h>

typedef struct {
    uint64_t w[80]; // work area
    uint64_t hash[8];
    uint64_t input[16];
    uint64_t input_size[2];
    size_t   input_idx;
} crypto_sha512_ctx;

void crypto_sha512_init  (crypto_sha512_ctx *ctx);
void crypto_sha512_update(crypto_sha512_ctx *ctx,
                          const uint8_t *message, size_t  message_size);
void crypto_sha512_final (crypto_sha512_ctx *ctx, uint8_t hash[64]);

void crypto_sha512(uint8_t *out,const uint8_t *message, size_t message_size);

#endif // SHA512_H
