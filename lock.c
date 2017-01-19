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

void crypto_lock_detached(const uint8_t  your_secret_key [32],
                          const uint8_t  their_public_key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *plaintext,
                          uint8_t       *ciphertext,
                          size_t         text_size,
                          uint8_t        mac[16])
{
    uint8_t shared_key[32];
    crypto_lock_key(shared_key, your_secret_key, their_public_key);
    crypto_ae_lock_detached(shared_key, nonce, plaintext, ciphertext,
                            text_size, mac);
}

int crypto_unlock_detached(const uint8_t  your_secret_key [32],
                           const uint8_t  their_public_key[32],
                           const uint8_t  nonce[24],
                           const uint8_t *ciphertext,
                           uint8_t       *plaintext,
                           size_t         text_size,
                           const uint8_t  mac[16])
{
    uint8_t shared_key[32];
    crypto_lock_key(shared_key, your_secret_key, their_public_key);
    return crypto_ae_unlock_detached(shared_key, nonce, ciphertext, plaintext,
                                     text_size, mac);
}

void crypto_lock(const uint8_t  your_secret_key [32],
                 const uint8_t  their_public_key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *plaintext,
                 size_t         text_size,
                 uint8_t       *box)
{
    crypto_lock_detached(your_secret_key, their_public_key, nonce,
                         plaintext, box + 16, text_size, box);
}

int crypto_unlock(const uint8_t  your_secret_key [32],
                  const uint8_t  their_public_key[32],
                  const uint8_t  nonce[24],
                  const uint8_t *box,
                  size_t         text_size,
                  uint8_t       *plaintext)
{
    return crypto_unlock_detached(your_secret_key, their_public_key, nonce,
                                  box + 16, plaintext, text_size, box);
}
