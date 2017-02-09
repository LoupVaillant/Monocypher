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

#endif // LOCK_H
