#ifndef LOCK_H
#define LOCK_H

#include <inttypes.h>
#include <stddef.h>

// Computes a shared key with your secret key and their public key,
// suitable for crypto_ae* functions.
void crypto_lock_key(uint8_t       shared_key      [32],
                     const uint8_t your_secret_key [32],
                     const uint8_t their_public_key[32]);

// Authenticated encryption with the sender's secret key and the recipient's
// publick key.  The message leaks if one of the secret key gets compromised.
void crypto_lock_detached(const uint8_t  your_secret_key [32],
                          const uint8_t  their_public_key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *plaintext,
                          uint8_t       *ciphertext,
                          size_t         text_size,
                          uint8_t        mac[16]);

// Authenticated decryption with the recipient's secret key, and the sender's
// public key.  Has no effect if the message is forged.
int crypto_unlock_detached(const uint8_t  your_secret_key [32],
                           const uint8_t  their_public_key[32],
                           const uint8_t  nonce[24],
                           const uint8_t *ciphertext,
                           uint8_t       *plaintext,
                           size_t         text_size,
                           const uint8_t  mac[16]);

// Like the above, only puts the mac and the ciphertext together
// in a "box", mac first
void crypto_lock(const uint8_t  your_secret_key [32],
                 const uint8_t  their_public_key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *plaintext,
                 size_t         text_size,
                 uint8_t       *box);

// Unlocks a box locked by crypto_lock()
int crypto_unlock(const uint8_t  your_secret_key [32],
                  const uint8_t  their_public_key[32],
                  const uint8_t  nonce[24],
                  const uint8_t *box,
                  size_t         text_size,
                  uint8_t       *plaintext);

#endif // LOCK_H
