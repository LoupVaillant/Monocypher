#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <inttypes.h>
#include <stddef.h>

// This is a chacha20 context.
// To use safely, just follow these guidelines:
// - Always initialize your context with one of the crypto_init_* functions below
// - Dont't modify it, except through the crypto_chacha20_* below.
// - Never duplicate it.
typedef struct crypto_chacha_ctx {
    uint32_t input[16];       // current input, unencrypted
    uint8_t  random_pool[64]; // last input, encrypted
    uint8_t  pool_index;      // pointer to random_pool
} crypto_chacha_ctx;

// HChacha20.  *Kind* of a cryptographic hash, based on the chacha20 rounds.
// Used for XChacha20, and the key derivation of the X25519 shared secret.
// Don't use it unless you really know what you're doing.
void
crypto_chacha20_H(uint8_t       out[32],
                  const uint8_t key[32],
                  const uint8_t in [16]);

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

// Initializes a chacha context, with a big nonce (192 bits),
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
// Decryption uses the exact same method.
//
// Once the context is initialized, encryptions can safely be chained thus:
//
//    crypto_encrypt_chacha20(ctx, plain_0, cipher_0, length_0);
//    crypto_encrypt_chacha20(ctx, plain_1, cipher_1, length_1);
//    crypto_encrypt_chacha20(ctx, plain_2, cipher_2, length_2);
//
// plain_text and cipher_text may point to the same location, for in-place
// encryption.
//
// plain_text is allowed to be null (0), in which case it will be
// interpreted as an all zero input.  The cipher_text will then
// contain the raw chacha20 stream.  Useful as a random number
// generator.
//
// WARNING: ENCRYPTION ALONE IS NOT SECURE.  YOU NEED AUTHENTICATION AS WELL.
// Use the provided authenticated encryption constructions.
void
crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                        const uint8_t     *plain_text,
                        uint8_t           *cipher_text,
                        size_t             message_size);

// convenience function.  Same as chacha20_encrypt() with a null plain_text.
void
crypto_chacha20_random(crypto_chacha_ctx *ctx,
                       uint8_t           *cipher_text,
                       size_t             message_size);


typedef struct {
    uint32_t r[4];
    uint32_t h[5];
    uint32_t c[5];
    uint32_t pad[5];
    size_t   c_index;
} crypto_poly1305_ctx;


// Initializes the poly1305 context with the secret key.
// Call first (obviously).
// WARNING: NEVER AUTHENTICATE 2 MESSAGES WITH THE SAME KEY.
// This is a ONE TIME authenticator.  If you authenticate 2 messages
// with the same key, the attacker may deduce your secret key and
// authenticate messages in your stead.
void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);

// Updates the poly1305 context with a chunk of the message
// Can be called multiple times, once for each chunk.
// Make sure the chunks are processed in order, without overlap or hole...
void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *m, size_t bytes);

// Authenticate the message munched through previous update() calls.
// Call last (obviously).
void crypto_poly1305_finish(crypto_poly1305_ctx *ctx, uint8_t mac[16]);


// Convenience all in one function
void crypto_poly1305_auth(uint8_t        mac[16],
                          const uint8_t *m,
                          size_t         msg_length,
                          const uint8_t  key[32]);

// Constant time equality verification
// returns 0 if it matches, something else otherwise.
int crypto_memcmp_16(const uint8_t mac1[16], const uint8_t mac2[16]);


// blake2b context
typedef struct {
    uint8_t  buf[128];      // input buffer
    uint64_t hash[8];       // chained state
    uint64_t input_size[2]; // total number of bytes
    uint8_t  c;             // pointer for buf[]
    uint8_t  output_size;   // digest size
} crypto_blake2b_ctx;

// Initializes the context with user defined parameters:
// outlen: the length of the hash.  Must be between 1 and 64.
// keylen: length of the key.       Must be between 0 and 64.
// key   : some secret key.         May be NULL if keylen is 0.
// Any deviation from these invariants results in UNDEFINED BEHAVIOR
void
crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t outlen,
                            const uint8_t      *key, size_t keylen);

// Convenience function: 64 bytes hash, no secret key.
void
crypto_blake2b_init(crypto_blake2b_ctx *ctx);

// Add "inlen" bytes from "in" into the hash.
void
crypto_blake2b_update(crypto_blake2b_ctx *ctx, const uint8_t *in, size_t inlen);

// Generate the message digest (size given in init).
void
crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *out);

// All-in-one convenience function.
// outlen, keylen, and key work the same as they do in the general_init function
void
crypto_blake2b_general(      uint8_t *out, size_t outlen, // digest
                       const uint8_t *key, size_t keylen, // optional secret key
                       const uint8_t *in , size_t inlen); // data to be hashed

// All-in-one convenience function: 64 bytes hash, no secret key.
void
crypto_blake2b(uint8_t out[64], const uint8_t *in, size_t inlen);



// Implements argon2i, with degree of paralelism 1,
// because it's good enough, and threads are scary.
//
// key and ad are optionnal.  They can be NULL if their respective size is 0.
// work_area is a pointer to a contiguous chunk of memory of at least
// nb_blocks * 1024 bytes.  It must be suitably aligned for 64-bit words.
// Don't worry too much about alignment, malloc()'s results work.
//
// Choice of parameters for password hashing:
// - If you need a key, use a 32 bytes one.
// - Do what you will with the ad.
// - Use a 32 bytes tag (to get a 256-bit key)
// - Put 128 bits of entropy in the salt.  16 random bytes work well.
// - Use all the memory you can get away with.
// - Use as much iterations as reasonable.  No less than 10 passes if you can.
void
crypto_argon2i_hash(uint8_t       *tag,       uint32_t tag_size,      // >= 4
                    const uint8_t *password,  uint32_t password_size,
                    const uint8_t *salt,      uint32_t salt_size,     // >= 8
                    const uint8_t *key,       uint32_t key_size,
                    const uint8_t *ad,        uint32_t ad_size,
                    void    *work_area,
                    uint32_t nb_blocks,                               // >= 8
                    uint32_t nb_iterations);

// Convenience function. No key, no ad, 64 bytes tag
void
crypto_argon2i(uint8_t        tag[32],
               const uint8_t *password,  uint32_t password_size,
               const uint8_t *salt,      uint32_t salt_size,     // >= 8
               void    *work_area,
               uint32_t nb_blocks,                               // >= 8
               uint32_t nb_iterations);


// Computes a shared secret from your private key and their public key.
// WARNING: DO NOT USE THE SHARED SECRET DIRECTLY.
// The shared secret is not pseudo-random.  You need to hash it to derive
// an acceptable secret key.  Any cryptographic hash can work, as well as
// HChacha20.
//
// Implementation details: this is an elliptic curve.  The public key is
// a point on this curve, and your private key is a scalar.  The shared
// secret is another point on this curve, obtained by scalar multiplication.
// Basically:
//     shared_secret == your_sk * their_pk == your_sk * (their_sk * base_point)
//                   == their_sk * your_pk == their_sk * (your_sk * base_point)
void crypto_x25519(uint8_t       shared_secret   [32],
                   const uint8_t your_secret_key [32],
                   const uint8_t their_public_key[32]);

// Generates a public key from the specified secret key.
// Make sure the secret key is randomly selected.
//
// Implementation detail: your secret key is a scalar, and we multiply
// the base point (a constant) by it to obtain a public key.  That is:
//     public_key == secret_key * base_point
// Reversing the operation is conjectured to be infeasible
// without quantum computers (128 bits of security).
void crypto_x25519_base(uint8_t public_key[32], const uint8_t secret_key[32]);


void crypto_ed25519_public_key(uint8_t        public_key[32],
                               const uint8_t  secret_key[32]);

void crypto_ed25519_sign(uint8_t        signature[64],
                         const uint8_t  secret_key[32],
                         const uint8_t *message,
                         size_t         message_size);

int crypto_ed25519_check(const uint8_t  signature[64],
                         const uint8_t  public_key[32],
                         const uint8_t *message,
                         size_t         message_size);


// Authenticated encryption with XChacha20 and Poly1305.
void crypto_ae_lock_detached(uint8_t        mac[16],
                             uint8_t       *ciphertext,
                             const uint8_t  key[32],
                             const uint8_t  nonce[24],
                             const uint8_t *plaintext,
                             size_t         text_size);

// Authenticated encryption with XChacha20 and Poly1305.
// Returns -1 and has no effect if the message is forged.
int crypto_ae_unlock_detached(uint8_t       *plaintext,
                              const uint8_t  key[32],
                              const uint8_t  nonce[24],
                              const uint8_t  mac[16],
                              const uint8_t *ciphertext,
                              size_t         text_size);

// Like the above, only puts the mac and the ciphertext together
// in a "box", mac first
void crypto_ae_lock(uint8_t       *box,      // text_size + 16
                    const uint8_t  key[32],
                    const uint8_t  nonce[24],
                    const uint8_t *plaintext,
                    size_t         text_size);

// Unlocks a box locked by aead_lock()
int crypto_ae_unlock(uint8_t       *plaintext,
                     const uint8_t  key[32],
                     const uint8_t  nonce[24],
                     const uint8_t *box,     // text_size + 16
                     size_t         text_size);


// Computes a shared key with your secret key and their public key,
// suitable for crypto_ae* functions.
void crypto_lock_key(uint8_t       shared_key      [32],
                     const uint8_t your_secret_key [32],
                     const uint8_t their_public_key[32]);

// Authenticated encryption with the sender's secret key and the recipient's
// public key.  The message leaks if one of the secret key gets compromised.
void crypto_lock_detached(uint8_t        mac[16],
                          uint8_t       *ciphertext,
                          const uint8_t  your_secret_key [32],
                          const uint8_t  their_public_key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *plaintext,
                          size_t         text_size);

// Authenticated decryption with the recipient's secret key, and the sender's
// public key.  Has no effect if the message is forged.
int crypto_unlock_detached(uint8_t       *plaintext,
                           const uint8_t  your_secret_key [32],
                           const uint8_t  their_public_key[32],
                           const uint8_t  nonce[24],
                           const uint8_t  mac[16],
                           const uint8_t *ciphertext,
                           size_t         text_size);

// Like the above, only puts the mac and the ciphertext together
// in a "box", mac first
void crypto_lock(uint8_t       *box,
                 const uint8_t  your_secret_key [32],
                 const uint8_t  their_public_key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *plaintext,
                 size_t         text_size);

// Unlocks a box locked by crypto_lock()
int crypto_unlock(uint8_t       *plaintext,
                  const uint8_t  your_secret_key [32],
                  const uint8_t  their_public_key[32],
                  const uint8_t  nonce[24],
                  const uint8_t *box,
                  size_t         text_size);

void crypto_anonymous_lock(uint8_t       *box,
                           const uint8_t  random_secret_key[32],
                           const uint8_t  their_public_key[32],
                           const uint8_t *plaintext,
                           size_t         text_size);

int crypto_anonymous_unlock(uint8_t       *plaintext,
                            const uint8_t  your_secret_key[32],
                            const uint8_t *box,
                            size_t         text_size);

#endif // MONOCYPHER_H
