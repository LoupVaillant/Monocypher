#include "lock.h"
#include "x25519.h"
#include "chacha20.h"
#include "ae.h"

void crypto_lock_key(uint8_t       shared_key[32],
                     const uint8_t your_secret_key [32],
                     const uint8_t their_public_key[32])
{
    static const uint8_t _0[16];
    uint8_t shared_secret[32];
    crypto_x25519(shared_secret, your_secret_key, their_public_key);
    crypto_chacha20_H(shared_key, shared_secret, _0);
}

void crypto_lock_detached(uint8_t        mac[16],
                          uint8_t       *ciphertext,
                          const uint8_t  your_secret_key [32],
                          const uint8_t  their_public_key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *plaintext,
                          size_t         text_size)
{
    uint8_t shared_key[32];
    crypto_lock_key(shared_key, your_secret_key, their_public_key);
    crypto_ae_lock_detached(mac, ciphertext,
                            shared_key, nonce,
                            plaintext, text_size);
}

int crypto_unlock_detached(uint8_t       *plaintext,
                           const uint8_t  your_secret_key [32],
                           const uint8_t  their_public_key[32],
                           const uint8_t  nonce[24],
                           const uint8_t  mac[16],
                           const uint8_t *ciphertext,
                           size_t         text_size)
{
    uint8_t shared_key[32];
    crypto_lock_key(shared_key, your_secret_key, their_public_key);
    return crypto_ae_unlock_detached(plaintext,
                                     shared_key, nonce,
                                     mac, ciphertext, text_size);
}

void crypto_lock(uint8_t       *box,
                 const uint8_t  your_secret_key [32],
                 const uint8_t  their_public_key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *plaintext,
                 size_t         text_size)
{
    crypto_lock_detached(box, box + 16,
                         your_secret_key, their_public_key, nonce,
                         plaintext, text_size);
}

int crypto_unlock(uint8_t       *plaintext,
                  const uint8_t  your_secret_key [32],
                  const uint8_t  their_public_key[32],
                  const uint8_t  nonce[24],
                  const uint8_t *box,
                  size_t         text_size)
{
    return crypto_unlock_detached(plaintext,
                                  your_secret_key, their_public_key, nonce,
                                  box, box + 16, text_size);
}

static const uint8_t null_nonce[24] = {};

void crypto_anonymous_lock(uint8_t       *box,
                           const uint8_t  random_secret_key[32],
                           const uint8_t  their_public_key[32],
                           const uint8_t *plaintext,
                           size_t         text_size)
{
    crypto_x25519_base(box, random_secret_key); // put public key in box
    crypto_lock(box + 32,
                random_secret_key, their_public_key, null_nonce,
                plaintext, text_size);
}

int crypto_anonymous_unlock(uint8_t       *plaintext,
                            const uint8_t  your_secret_key[32],
                            const uint8_t *box,
                            size_t         text_size)
{
    return crypto_unlock(plaintext,
                         your_secret_key, box, null_nonce,
                         box + 32, text_size);
}
