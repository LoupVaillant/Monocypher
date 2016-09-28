#ifndef POLY1305_H
#define POLY1305_H

#include <inttypes.h>
#include <stddef.h>

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t   leftover;
    uint8_t  buffer[16];
    uint8_t  final;
} crypto_poly1305_ctx;

// Initializes the poly1305 context with the secret key.
// Call first (obviously).
// WARNING: NEVER AUTHENTICATE 2 MESSAGES WITH THE SAME KEY.
// This is a ONE TIME authenticator.  If you authenticate 2 messages
// with the same key, the attacker may deduce your secret key and
// authenticate messages in your stead.
void
crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);

// Updates the poly1305 context with a chunk of the message
// Can be called multiple times, once for each chunk.
// Make sure the chunks are processed in order, without overlap or hole...
void
crypto_poly1305_update(crypto_poly1305_ctx *ctx, const uint8_t *m, size_t bytes);

// Authenticate the message munched through previous update() calls.
// Call last (obviously).
void
crypto_poly1305_finish(crypto_poly1305_ctx *ctx, uint8_t mac[16]);


// Convenience all in one function
void
crypto_poly1305_auth(uint8_t        mac[16],
                     const uint8_t *m,
                     size_t         msg_length,
                     const uint8_t  key[32]);

// Constant time equality verification
// returns 1 if it matches, 0 otherwise.
int
crypto_poly1305_verify(const uint8_t mac1[16], const uint8_t mac2[16]);

#endif // POLY1305_H
