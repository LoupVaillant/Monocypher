#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <inttypes.h>

typedef struct {
    uint64_t h[8];
    uint64_t m[16];
    uint64_t m_size[2];
    size_t   m_index;
} crypto_sha512_ctx;

void crypto_sha512_init  (crypto_sha512_ctx *ctx);
void crypto_sha512_update(crypto_sha512_ctx *ctx,
                          const uint8_t     *in, size_t  inlen);
void crypto_sha512_finish(crypto_sha512_ctx *ctx, uint8_t out[64]);

void crypto_sha512(uint8_t *out,const uint8_t *input, size_t input_size);

#endif // SHA512_H
