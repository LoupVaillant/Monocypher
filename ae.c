#include "ae.h"
#include "chacha20.h"
#include "poly1305.h"

void crypto_ae_lock_detached(uint8_t        mac[16],
                             uint8_t       *ciphertext,
                             const uint8_t  key[32],
                             const uint8_t  nonce[24],
                             const uint8_t *plaintext,
                             size_t         text_size)
{
    crypto_chacha_ctx e_ctx;
    uint8_t           auth_key[32];
    crypto_chacha20_Xinit (&e_ctx, key, nonce);
    crypto_chacha20_random(&e_ctx, auth_key, 32);

    crypto_chacha20_encrypt(&e_ctx, plaintext, ciphertext, text_size);
    crypto_poly1305_auth(mac, ciphertext, text_size, auth_key);
}

int crypto_ae_unlock_detached(uint8_t       *plaintext,
                              const uint8_t  key[32],
                              const uint8_t  nonce[24],
                              const uint8_t  mac[16],
                              const uint8_t *ciphertext,
                              size_t         text_size)
{
    crypto_chacha_ctx e_ctx;
    uint8_t           auth_key[32];
    crypto_chacha20_Xinit (&e_ctx, key, nonce);
    crypto_chacha20_random(&e_ctx, auth_key, 32);

    uint8_t real_mac[16];
    crypto_poly1305_auth(real_mac, ciphertext, text_size, auth_key);

    if (crypto_memcmp_16(real_mac, mac))
        return -1;

    crypto_chacha20_encrypt(&e_ctx, ciphertext, plaintext, text_size);
    return 0;
}

void crypto_ae_lock(uint8_t       *box,
                    const uint8_t  key[32],
                    const uint8_t  nonce[24],
                    const uint8_t *plaintext,
                    size_t         text_size)
{
    crypto_ae_lock_detached(box, box + 16, key, nonce, plaintext, text_size);
}

int crypto_ae_unlock(uint8_t       *plaintext,
                     const uint8_t  key[32],
                     const uint8_t  nonce[24],
                     const uint8_t *box,
                     size_t         text_size)
{
    return crypto_ae_unlock_detached(plaintext, key, nonce,
                                     box, box + 16, text_size);
}
