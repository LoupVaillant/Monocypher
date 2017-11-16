#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <inttypes.h>
#include <stddef.h>

// Constant time comparisons.
// Return 0 if a and b are equal, -1 otherwise
int crypto_verify16(const uint8_t a[16], const uint8_t b[16]);
int crypto_verify32(const uint8_t a[32], const uint8_t b[32]);
int crypto_verify64(const uint8_t a[64], const uint8_t b[64]);

// Erase a buffer from existence.
// It probably wasn't the only copy...
void crypto_wipe(void *secret, size_t size);

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

void crypto_poly1305(uint8_t        mac[16],
                     const uint8_t *message, size_t message_size,
                     const uint8_t  key[32]);

// Deprecated name
#define crypto_poly1305_auth crypto_poly1305

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
void crypto_argon2i_general(uint8_t       *hash,      uint32_t hash_size, // >= 4
                            void          *work_area, uint32_t nb_blocks, // >= 8
                            uint32_t       nb_iterations,                 // >= 1
                            const uint8_t *password,  uint32_t password_size,
                            const uint8_t *salt,      uint32_t salt_size, // >= 8
                            const uint8_t *key,       uint32_t key_size,
                            const uint8_t *ad,        uint32_t ad_size);

void crypto_argon2i(uint8_t       *hash,      uint32_t hash_size,     // >= 4
                    void          *work_area, uint32_t nb_blocks,     // >= 8
                    uint32_t       nb_iterations,                     // >= 1
                    const uint8_t *password,  uint32_t password_size,
                    const uint8_t *salt,      uint32_t salt_size);

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

#ifdef ED25519_SHA512
typedef crypto_sha512_ctx crypto_hash_ctx;
#else
typedef crypto_blake2b_ctx crypto_hash_ctx;
#endif

// EdDSA signatures context.  Do not rely on its contents or its size,
// they may change without notice.
typedef struct {
    crypto_hash_ctx hash;
    uint8_t buf[96];
    uint8_t pk [32];
} crypto_sign_ctx;

void crypto_sign_init_first_pass(crypto_sign_ctx *ctx,
                                 const uint8_t  secret_key[32],
                                 const uint8_t  public_key[32]);

void crypto_sign_update(crypto_sign_ctx *ctx,
                        const uint8_t *message, size_t message_size);

void crypto_sign_init_second_pass(crypto_sign_ctx *ctx);

void crypto_sign_final(crypto_sign_ctx *ctx, uint8_t signature[64]);

void crypto_sign(uint8_t        signature [64],
                 const uint8_t  secret_key[32],
                 const uint8_t  public_key[32], // optional, may be 0
                 const uint8_t *message, size_t message_size);

int crypto_check_public_key(const uint8_t public_key[32]);

// EdDSA check context.  Do not rely on its contents or its size, they
// may change without notice.
typedef struct {
    crypto_hash_ctx hash;
    uint8_t sig[64];
    uint8_t pk [32];
} crypto_check_ctx;

void crypto_check_init(crypto_check_ctx *ctx,
                       const uint8_t signature[64],
                       const uint8_t public_key[32]);

void crypto_check_update(crypto_check_ctx *ctx,
                         const uint8_t *message, size_t message_size);

int crypto_check_final(crypto_check_ctx *ctx);

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

// Authenticated encryption context.  Do not rely on its contents or
// its size, they may change without notice.
typedef struct {
    crypto_chacha_ctx   chacha;
    crypto_poly1305_ctx poly;
} crypto_lock_ctx;

void crypto_lock_init(crypto_lock_ctx *ctx,
                      const uint8_t    key[32],
                      const uint8_t    nonce[24]);

void crypto_lock_auth(crypto_lock_ctx *ctx,
                      const uint8_t   *message,
                      size_t           message_size);

void crypto_lock_encrypt(crypto_lock_ctx *ctx,
                         uint8_t         *cipher_text,
                         const uint8_t   *plain_text,
                         size_t           text_size);

void crypto_lock_update(crypto_lock_ctx *ctx,
                        uint8_t         *cipher_text,
                        const uint8_t   *plain_text,
                        size_t           text_size);

void crypto_unlock_update(crypto_lock_ctx *ctx,
                          uint8_t         *plain_text,
                          const uint8_t   *cipher_text,
                          size_t           text_size);

void crypto_lock_final(crypto_lock_ctx *ctx, uint8_t mac[16]);

int crypto_unlock_final(crypto_lock_ctx *ctx, const uint8_t mac[16]);

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

#endif // MONOCYPHER_H
