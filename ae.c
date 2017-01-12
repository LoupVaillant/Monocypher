#include "ae.h"
#include "chacha20.h"
#include "poly1305.h"

void
crypto_ae_lock_detached(const uint8_t  key[32],
                        const uint8_t  nonce[24],
                        const uint8_t *plaintext,
                        uint8_t       *ciphertext,
                        size_t         text_size,
                        uint8_t        mac[16])
{
    crypto_chacha_ctx e_ctx;
    uint8_t           auth_key[32];
    crypto_chacha20_Xinit (&e_ctx, key, nonce);
    crypto_chacha20_random(&e_ctx, auth_key, 32);

    crypto_chacha20_encrypt(&e_ctx, plaintext, ciphertext, text_size);
    crypto_poly1305_auth(mac, ciphertext, text_size, auth_key);
}

int
crypto_ae_unlock_detached(const uint8_t  key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *ciphertext,
                          uint8_t       *plaintext,
                          size_t         text_size,
                          const uint8_t  mac[16])
{
    crypto_chacha_ctx e_ctx;
    uint8_t           auth_key[32];
    crypto_chacha20_Xinit (&e_ctx, key, nonce);
    crypto_chacha20_random(&e_ctx, auth_key, 32);

    uint8_t real_mac[16];
    crypto_poly1305_auth(real_mac, ciphertext, text_size, auth_key);

    if (crypto_poly1305_verify(real_mac, mac))
        return -1;

    crypto_chacha20_encrypt(&e_ctx, ciphertext, plaintext, text_size);
    return 0;
}

void
crypto_ae_lock(const uint8_t  key[32],
               const uint8_t  nonce[24],
               const uint8_t *plaintext,
               size_t         text_size,
               uint8_t       *box)
{
    crypto_ae_lock_detached(key, nonce, plaintext, box + 16, text_size, box);
}

int
crypto_ae_unlock(const uint8_t  key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *box,
                 size_t         text_size,
                 uint8_t       *plaintext)
{
    return crypto_ae_unlock_detached(key, nonce, box + 16,
                                     plaintext, text_size, box);
}
