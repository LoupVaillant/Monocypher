#ifndef __CHACHA20__
#define __CHACHA20__

#include <inttypes.h>
#include <stddef.h>

typedef struct crypto_chacha_ctx {
    uint32_t input[16];
} crypto_chacha_ctx;

typedef struct crypto_rng_context {
    crypto_chacha_ctx chacha_ctx;
    uint8_t           reminder[64];
    size_t            remaining_bytes;
} crypto_rng_context;

// Encrypts the plain_text by XORing it with a pseudo-random
// stream of numbers, seeded by the key and the nonce.
// NEVER ENCRYPT 2 DISTINCT MESSAGES WITH THE SAME KEY AND NONCE.
// If you do, you will expose the XOR of the two messages, and your
// confidentiality is toast.  One time pads are called one time pads
// for a reason.
//
// To decrypt a message, encrypt it again with the same key and nonce.
//
// key        : Your secret key.  Chose a (pseudo-)random one!
// nonce      : Only once per key. Seriously, don't mess this up.
// ctr        : Initial counter value. Typically 0 or 1
// plain_text : Your precious secret message
// cipher_text: Output buffer
// msg_length : Length of plain_text and cipher_text
void
crypto_encrypt_chacha20(const uint8_t  key[32],
                        const uint8_t  nonce[8],
                        uint64_t       ctr,
                        const uint8_t *plain_text,
                        uint8_t       *cipher_text,
                        size_t         msg_length);

// This one is very similar to encrypt_chacha20, except it provides
// a nonce large enough to chose at random, withouth worrying about
// collisions.  Handy for stateless protocols.
//
// Streaming performance is the same, initialization is a bit slower.
void
crypto_encrypt_Xchacha20(const uint8_t  key[32],
                         const uint8_t  nonce[24],
                         uint64_t       ctr,
                         const uint8_t *plain_text,
                         uint8_t       *cipher_text,
                         size_t         msg_length);

// Will look random as long as you never use the same input twice.
// Can be used with encrypt_bytes as long as the counter here is smaller
// than the encrypt_bytes counter, and the message is not long enough to
// wrap around the counter.
// Use 1 for the encrypt_bytes counter and 0 here, and you should be safe.
void
crypto_block_chacha20(const uint8_t key[32],
                      const uint8_t nonce[8],
                      uint64_t      ctr,
                      uint8_t       output[64]);

// Similar to block_chacha20, except for the big nonce and worse performance.
void
crypto_block_Xchacha20(const uint8_t key[32],
                       const uint8_t nonce[24],
                       uint64_t      ctr,
                       uint8_t       output[64]);



// Inits a cryptographically secure Random Number Generator, with the
// given key and nonce.  The output of that RNG will depend entirely
// on the key and nonce.
// NEVER USE THE SAME KEY AND NONCE FOR THIS AND MESSAGE ENCRYPTION.
// If you do, you could leak the very key stream used to encrypt
// your messages.  They'd be instantly deciphered.
void
crypto_init_rng(crypto_rng_context *ctx,
                const uint8_t       key[32],
                const uint8_t       nonce[8]);

// provides pseudo-random bytes, deterministically (the output and
// the end state of ctx depends entirely on the initial state of ctx).
// It's a chacha20 stream, really.
void
crypto_random_bytes(crypto_rng_context *ctx,
                    uint8_t            *out,
                    size_t              nb_bytes);

#endif // __CHACHA20__
