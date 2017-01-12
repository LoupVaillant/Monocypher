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
    uint32_t input[16];       // current input, unencrypted
    uint8_t  random_pool[64]; // last input, encrypted
    uint8_t  pool_index;      // pointer to random_pool
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
crypto_chacha20_init(crypto_chacha_ctx *ctx,
                     const uint8_t      key[32],
                     const uint8_t      nonce[8]);

// Initializes a chacha context, with an even bigger nonce (192 bits),
// more than enough to be selected at random.
//
// The price you pay for that is a slower initialization.  The security
// guarantees are the same as regular initialization.
void
crypto_chacha20_Xinit(crypto_chacha_ctx *ctx,
                      const uint8_t      key[32],
                      const uint8_t      nonce[24]);

// Encrypts the plain_text by XORing it with a pseudo-random
// stream of numbers, seeded by the provided chacha20 context.
// It can safely be chained thus:
//
//    crypto_encrypt_chacha20(ctx, plaint_0, cipher_0, length_0);
//    crypto_encrypt_chacha20(ctx, plaint_1, cipher_1, length_1);
//    crypto_encrypt_chacha20(ctx, plaint_2, cipher_2, length_2);
//
// plain_text is allowed to be null (0), in which case it will be
// interpreted as an all zero input.  The cipher_text will then
// contain the raw chacha20 stream.  Useful as a random number
// generator.
void
crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                        const uint8_t     *plain_text,
                        uint8_t           *cipher_text,
                        size_t             msg_length);

// convenience function.
// equivalent to encrypt_chacha20(ctx, 0, cipher_text, msg_length)
void
crypto_chacha20_random(crypto_chacha_ctx *ctx,
                       uint8_t           *cipher_text,
                       size_t             msg_length);

#endif // CHACHA20_H
