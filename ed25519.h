#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>
#include <inttypes.h>

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

#endif // ED25519_H
