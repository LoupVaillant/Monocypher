// Deprecated incremental API for Chacha20
//
// This file *temporarily* provides compatibility with Monocypher 2.x.
// Do not rely on its continued existence.
//
// Deprecated in     : 3.0.0
// Will be removed in: 4.0.0
//
// Deprecated functions & types:
//     crypto_chacha_ctx
//     crypto_chacha20_H
//     crypto_chacha20_init
//     crypto_chacha20_x_init
//     crypto_chacha20_set_ctr
//     crypto_chacha20_encrypt
//     crypto_chacha20_stream
//
// For existing deployments that can no longer be updated or modified,
// use the 2.x family, which will receive security updates until 2024.
//
// Upgrade strategy:
// The new 3.x API can emulate incremental capabilities by setting a
// custom counter.  Make sure you authenticate each chunk before you
// decrypt them, though.

#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <inttypes.h>

// Chacha20
typedef struct {
    uint8_t  key[32];
    uint8_t  nonce[8];
    uint64_t ctr;
    uint8_t  pool[64];
    size_t   pool_idx;
} crypto_chacha_ctx;

// Chacha20 (old API)
// ------------------

// Specialised hash.
void crypto_chacha20_H(uint8_t       out[32],
                       const uint8_t key[32],
                       const uint8_t in [16]);

void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                          const uint8_t      key[32],
                          const uint8_t      nonce[8]);

void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                            const uint8_t      key[32],
                            const uint8_t      nonce[24]);

void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, uint64_t ctr);

void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                             uint8_t           *cipher_text,
                             const uint8_t     *plain_text,
                             size_t             text_size);

void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
                            uint8_t *stream, size_t size);


#endif // CHACHA20_H
