#ifndef AE_H
#define AE_H

#include <inttypes.h>
#include <stddef.h>


// Authenticated encryption with XChacha20 and Poly1305.
void
crypto_ae_lock_detached(const uint8_t  key[32],
                        const uint8_t  nonce[24],
                        const uint8_t *plaintext,
                        uint8_t       *ciphertext,
                        size_t         text_size,
                        uint8_t        mac[16]);

// Authenticated encryption with XChacha20 and Poly1305.
// Returns -1 and has no effect if the message is forged.
int
crypto_ae_unlock_detached(const uint8_t  key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *ciphertext,
                          uint8_t       *plaintext,
                          size_t         text_size,
                          const uint8_t  mac[16]);

// Like the above, only puts the mac and the ciphertext together
// in a "box", mac first
void
crypto_ae_lock(const uint8_t  key[32],
               const uint8_t  nonce[24],
               const uint8_t *plaintext,
               size_t         text_size,
               uint8_t       *box);      // text_size + 16

// Unlocks a box locked by aead_lock()
int
crypto_ae_unlock(const uint8_t  key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *box,     // text_size + 16
                 size_t         text_size,
                 uint8_t       *plaintext);





#endif // AE_H
