// Deprecated incremental API for authenticated encryption
//
// This file *temporarily* provides compatibility with Monocypher 2.x.
// Do not rely on its continued existence.
//
// Deprecated in     : 3.0.0
// Will be removed in: 4.0.0
//
// Deprecated functions & types:
//     crypto_unlock_ctx
//     crypto_lock_ctx
//     crypto_lock_init
//     crypto_lock_auth_ad
//     crypto_lock_auth_message
//     crypto_lock_update
//     crypto_lock_final
//     crypto_unlock_init
//     crypto_unlock_auth_ad
//     crypto_unlock_auth_message
//     crypto_unlock_update
//     crypto_unlock_final
//
// For existing deployments that can no longer be updated or modified,
// use the 2.x family, which will receive security updates until 2024.
//
// upgrade strategy:
// Change your protocol in a way that it does not rely on the removed
// functions, namely by splitting the file into chunks you each use the
// crypto_lock() and crypto_unlock() functions on.
//
// For files, you may alternatively (and suboptimally) attempt to
// mmap()/MapViewOfFile() and pass the files as mapped memory into
// crypto_lock() and crypto_unlock() this way instead.

#ifndef AEAD_INCR_H
#define AEAD_INCR_H

#include <stddef.h>
#include <inttypes.h>
#include "monocypher.h"
#include "deprecated/chacha20.h"

typedef struct {
    crypto_chacha_ctx   chacha;
    crypto_poly1305_ctx poly;
    uint64_t            ad_size;
    uint64_t            message_size;
    int                 ad_phase;
} crypto_lock_ctx;
#define crypto_unlock_ctx crypto_lock_ctx

// Encryption
void crypto_lock_init(crypto_lock_ctx *ctx,
                      const uint8_t    key[32],
                      const uint8_t    nonce[24]);
void crypto_lock_auth_ad(crypto_lock_ctx *ctx,
                         const uint8_t   *message,
                         size_t           message_size);
void crypto_lock_auth_message(crypto_lock_ctx *ctx,
                              const uint8_t *cipher_text, size_t text_size);
void crypto_lock_update(crypto_lock_ctx *ctx,
                        uint8_t         *cipher_text,
                        const uint8_t   *plain_text,
                        size_t           text_size);
void crypto_lock_final(crypto_lock_ctx *ctx, uint8_t mac[16]);

// Decryption
#define crypto_unlock_init         crypto_lock_init
#define crypto_unlock_auth_ad      crypto_lock_auth_ad
#define crypto_unlock_auth_message crypto_lock_auth_message
void crypto_unlock_update(crypto_unlock_ctx *ctx,
                          uint8_t           *plain_text,
                          const uint8_t     *cipher_text,
                          size_t             text_size);
int crypto_unlock_final(crypto_unlock_ctx *ctx, const uint8_t mac[16]);

#endif // AEAD_INCR_H
