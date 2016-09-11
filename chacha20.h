#ifndef CHACHA20_H
#define CHACHA20_H

#include <inttypes.h>
#include <stddef.h>

// This is a chacha20 context.
// To use safely, just follow these guidelines:
// - Always initialize your context with one of the crypto_init_* functions below
// - Dont't modify it, except through the crypto_*_chacha20 below.
// - Never duplicate it.
typedef struct crypto_chacha_ctx {
    uint32_t input[16];
} crypto_chacha_ctx;

// Initializes a chacha context.
//
// WARNING: DON'T USE THE SAME NONCE AND KEY TWICE
//
// You'd be exposing the XOR of subsequent encrypted
// messages, thus destroying your confidentiality.
//
// WARNING: DON'T SELECT THE NONCE AT RANDOM
//
// If you encode enough messages with a random nonce, there's a good
// chance some of them will use the same nonce by accident. 64 bits
// just isn't enough for this.  Use a counter instead.
//
// If there are multiple parties sending out messages, you can give them
// all an initial nonce of 0, 1 .. n-1 respectively, and have them increment
// their nonce  by n.  (Also make sure the nonces never wrap around.).
void
crypto_init_chacha20(crypto_chacha_ctx *ctx,
                     const uint8_t      key[32],
                     const uint8_t      nonce[8]);

// Initializes a chacha context, with a bigger nonce (192 bits).
//
// It's slower than regular initialization, but that big nonce can now
// be selected at random without fear of collision.  No more complex,
// stateful headache.
void
crypto_init_Xchacha20(crypto_chacha_ctx *ctx,
                      const uint8_t      key[32],
                      const uint8_t      nonce[24]);

// Outputs a single block from the provided context, then increments
// the counter of that context by 1.  Can safely be called several
// times over the same context like this:
//    crypto_block_chacha20(output      , ctx);
//    crypto_block_chacha20(output +  64, ctx);
//    crypto_block_chacha20(output + 128, ctx);
//    crypto_block_chacha20(output + 192, ctx);
// Since che context will in fact have been changed at each call,
// the resulting outputs will be completely different.
void
crypto_block_chacha20(uint8_t output[64], crypto_chacha_ctx *ctx);

// Encrypts the plain_text by XORing it with a pseudo-random
// stream of numbers, seeded by the provided chacha20 context.
// It is built on top of crypto_chacha20_block, and can be safely
// used with it, thus:
//
//    crypto_block_chacha20(output, ctx);
//    crypto_encrypt_chacha20(ctx, plaint_t, cipher_t, length);
void
crypto_encrypt_chacha20(crypto_chacha_ctx *ctx,
                        const uint8_t     *plain_text,
                        uint8_t           *cipher_text,
                        size_t             msg_length);


////////////////////////////////////////////////////////////////////////////////

typedef struct crypto_rng_context {
    crypto_chacha_ctx chacha_ctx;
    uint8_t           reminder[64];
    size_t            remaining_bytes;
} crypto_rng_context;

// Inits a cryptographically secure Random Number Generator, with the
// given key and nonce.  The output of that RNG will depend entirely
// on the key and nonce.
// NEVER USE THE SAME KEY FOR THIS AND MESSAGE ENCRYPTION.
// If you do, you could leak the very key stream used to encrypt
// your messages.  They'd be instantly deciphered.
void
crypto_init_rng(crypto_rng_context *ctx, const uint8_t key[32]);

// provides pseudo-random bytes, deterministically (the output and
// the end state of ctx depends entirely on the initial state of ctx).
// It's a chacha20 stream, really.
void
crypto_random_bytes(crypto_rng_context *ctx, uint8_t *out, size_t nb_bytes);

#endif // CHACHA20_H
