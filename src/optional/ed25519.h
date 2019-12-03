// Monocypher version __git__

#ifndef ED25519_H
#define ED25519_H

#include "monocypher.h"

////////////////////////
/// Type definitions ///
////////////////////////

// Do not rely on the size or content on any of those types,
// they may change without notice.
typedef struct {
    uint64_t hash[8];
    uint64_t input[16];
    uint64_t input_size[2];
    size_t   input_idx;
} crypto_sha512_ctx;

typedef struct {
    uint8_t key[128];
    crypto_sha512_ctx ctx;
} crypto_hmac_ctx;

typedef struct {
    crypto_sign_ctx_abstract ctx;
    crypto_sha512_ctx        hash;
} crypto_sign_ed25519_ctx;
typedef crypto_sign_ed25519_ctx crypto_check_ed25519_ctx;

// SHA 512
// -------
void crypto_sha512_init  (crypto_sha512_ctx *ctx);
void crypto_sha512_update(crypto_sha512_ctx *ctx,
                          const uint8_t *message, size_t  message_size);
void crypto_sha512_final (crypto_sha512_ctx *ctx, uint8_t hash[64]);
void crypto_sha512(uint8_t *hash, const uint8_t *message, size_t message_size);

// vtable for signatures
extern const crypto_sign_vtable crypto_sha512_vtable;


// HMAC SHA 512
// ------------
void crypto_hmac_init(crypto_hmac_ctx *ctx,
                      const uint8_t *key, size_t key_size);
void crypto_hmac_update(crypto_hmac_ctx *ctx,
                        const uint8_t *message, size_t  message_size);
void crypto_hmac_final(crypto_hmac_ctx *ctx, uint8_t hmac[64]);
void crypto_hmac(uint8_t *hmac,
                 const uint8_t *key    , size_t key_size,
                 const uint8_t *message, size_t message_size);


// Ed25519
// -------

// Generate public key
void crypto_ed25519_public_key(uint8_t       public_key[32],
                               const uint8_t secret_key[32]);

// Direct interface
void crypto_ed25519_sign(uint8_t        signature [64],
                         const uint8_t  secret_key[32],
                         const uint8_t  public_key[32], // optional, may be 0
                         const uint8_t *message, size_t message_size);
int crypto_ed25519_check(const uint8_t  signature [64],
                         const uint8_t  public_key[32],
                         const uint8_t *message, size_t message_size);

// Incremental interface
void crypto_ed25519_sign_init_first_pass(crypto_sign_ctx_abstract *ctx,
                                         const uint8_t secret_key[32],
                                         const uint8_t public_key[32]);
#define crypto_ed25519_sign_update crypto_sign_update
#define crypto_ed25519_sign_init_second_pass crypto_sign_init_second_pass
// use crypto_ed25519_sign_update() again.
#define crypto_ed25519_sign_final crypto_sign_final

void crypto_ed25519_check_init(crypto_check_ctx_abstract *ctx,
                               const uint8_t signature[64],
                               const uint8_t public_key[32]);
#define crypto_ed25519_check_update crypto_check_update
#define crypto_ed25519_check_final crypto_check_final


#endif // ED25519_H
