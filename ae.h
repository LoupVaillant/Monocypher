#ifndef AE_H
#define AE_H

#include <inttypes.h>
#include <stddef.h>


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





#endif // AE_H
