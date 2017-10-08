#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <inttypes.h>
#include <stddef.h>

// Constant time equality verification
// returns 0 if it matches, -1 otherwise.
int crypto_memcmp(const uint8_t *p1, const uint8_t *p2, size_t n);

// constant time zero comparison.
// returns 0 if the input is all zero, -1 otherwise.
int crypto_zerocmp(const uint8_t *p, size_t n);

////////////////
/// Chacha20 ///
////////////////

// Chacha context.  Do not rely on its contents or its size,
// they may change without notice.
typedef struct {
    uint32_t input[16]; // current input, unencrypted
    uint32_t pool [16]; // last input, encrypted
    size_t   pool_idx;  // pointer to random_pool
} crypto_chacha_ctx;

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

/////////////////
/// Poly 1305 ///
/////////////////

// Poly 1305 context.  Do not rely on its contents or its size, they
// may change without notice.
typedef struct {
    uint32_t r[4];   // constant multiplier (from the secret key)
    uint32_t h[5];   // accumulated hash
    uint32_t c[5];   // chunk of the message
    uint32_t pad[4]; // random number added at the end (from the secret key)
    size_t   c_idx;  // How many bytes are there in the chunk.
} crypto_poly1305_ctx;

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *message, size_t message_size);

void crypto_poly1305_final(crypto_poly1305_ctx *ctx, uint8_t mac[16]);

void crypto_poly1305_auth(uint8_t        mac[16],
                          const uint8_t *message, size_t message_size,
                          const uint8_t  key[32]);

////////////////
/// Blake2 b ///
////////////////

// Blake2b context.  Do not rely on its contents or its size, they
// may change without notice.
typedef struct {
    uint64_t hash[8];
    uint64_t input_offset[2];
    uint64_t input[16];
    size_t   input_idx;
    size_t   hash_size;
} crypto_blake2b_ctx;

void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                                 const uint8_t      *key, size_t key_size);

void crypto_blake2b_init(crypto_blake2b_ctx *ctx);

void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const uint8_t *message, size_t message_size);

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash);

void crypto_blake2b_general(uint8_t       *hash    , size_t hash_size,
                            const uint8_t *key     , size_t key_size, // optional
                            const uint8_t *message , size_t message_size);

void crypto_blake2b(uint8_t hash[64],
                    const uint8_t *message, size_t message_size);

////////////////
/// Argon2 i ///
////////////////
void crypto_argon2i(uint8_t       *hash,      uint32_t hash_size,     // >= 4
                    void          *work_area, uint32_t nb_blocks,     // >= 8
                    uint32_t       nb_iterations,                     // >= 1
                    const uint8_t *password,  uint32_t password_size,
                    const uint8_t *salt,      uint32_t salt_size,     // >= 8
                    const uint8_t *key,       uint32_t key_size,      // optional
                    const uint8_t *ad,        uint32_t ad_size);      // optional

///////////////
/// X-25519 ///
///////////////
int crypto_x25519(uint8_t       raw_shared_secret[32],
                  const uint8_t your_secret_key  [32],
                  const uint8_t their_public_key [32]);

void crypto_x25519_public_key(uint8_t       public_key[32],
                              const uint8_t secret_key[32]);


/////////////
/// EdDSA ///
/////////////
void crypto_sign_public_key(uint8_t        public_key[32],
                            const uint8_t  secret_key[32]);

void crypto_sign(uint8_t        signature [64],
                 const uint8_t  secret_key[32],
                 const uint8_t  public_key[32], // optional, may be 0
                 const uint8_t *message, size_t message_size);

#define COMBINE1(x, y) x ## y
#define COMBINE2(x, y) COMBINE1(x, y)
#define HASH_CTX    COMBINE2(HASH, _ctx)
#define HASH_INIT   COMBINE2(HASH, _init)
#define HASH_UPDATE COMBINE2(HASH, _update)
#define HASH_FINAL  COMBINE2(HASH, _final)

typedef struct { int32_t X[10]; int32_t Y[10]; int32_t Z[10]; int32_t T[10];
} ge;
typedef struct {
#ifdef ED25519_SHA512
    crypto_sha512_ctx  hash_ctx;
#else
    crypto_blake2b_ctx hash_ctx;
#endif
    ge  A;
    int invalid_pk;
} crypto_check_ctx;

int crypto_check_init(crypto_check_ctx *ctx,
                      const uint8_t signature[64],
                      const uint8_t public_key[32]);

void crypto_check_update(crypto_check_ctx *ctx,
                         const uint8_t *message, size_t message_size);

int crypto_check_final(crypto_check_ctx *ctx, const uint8_t signature[64]);

int crypto_check(const uint8_t  signature [64],
                 const uint8_t  public_key[32],
                 const uint8_t *message, size_t message_size);

////////////////////
/// Key exchange ///
////////////////////
int crypto_key_exchange(uint8_t       shared_key      [32],
                        const uint8_t your_secret_key [32],
                        const uint8_t their_public_key[32]);

////////////////////////////////
/// Authenticated encryption ///
////////////////////////////////
void crypto_aead_lock(uint8_t        mac[16],
                      uint8_t       *cipher_text,
                      const uint8_t  key[32],
                      const uint8_t  nonce[24],
                      const uint8_t *ad        , size_t ad_size,
                      const uint8_t *plain_text, size_t text_size);

int crypto_aead_unlock(uint8_t       *plain_text,
                       const uint8_t  key[32],
                       const uint8_t  nonce[24],
                       const uint8_t  mac[16],
                       const uint8_t *ad         , size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

void crypto_lock(uint8_t        mac[16],
                 uint8_t       *cipher_text,
                 const uint8_t  key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *plain_text, size_t text_size);

int crypto_unlock(uint8_t       *plain_text,
                  const uint8_t  key[32],
                  const uint8_t  nonce[24],
                  const uint8_t  mac[16],
                  const uint8_t *cipher_text, size_t text_size);

typedef struct {
    crypto_chacha_ctx   chacha;
    crypto_poly1305_ctx poly;
} crypto_lock_ctx;

void crypto_lock_init(crypto_lock_ctx *ctx,
                      const uint8_t key[32],
                      const uint8_t nonce[24]);

void crypto_lock_auth(crypto_lock_ctx *ctx,
                      const uint8_t *ad, size_t ad_size);

void crypto_lock_update(crypto_lock_ctx *ctx,
                        uint8_t *cipher_text,
                        const uint8_t *plain_text, size_t text_size);

void crypto_lock_final(crypto_lock_ctx *ctx, uint8_t mac[16]);

void crypto_unlock_update(crypto_lock_ctx *ctx,
                          uint8_t *plain_text,
                          const uint8_t *cipher_text, size_t text_size);

int crypto_unlock_final(crypto_lock_ctx *ctx, const uint8_t mac[16]);

#endif // MONOCYPHER_H
