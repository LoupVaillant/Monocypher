#include <sodium.h>

typedef crypto_generichash_state ed25519_hash_context;

void ed25519_hash_init(ed25519_hash_context *ctx)
{
    crypto_generichash_init(ctx, 0, 0, 64);
}

void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen)
{
    crypto_generichash_update(ctx, in, inlen);
}

void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash)
{
    crypto_generichash_final(ctx, hash, 64);
}

void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen)
{
    crypto_generichash(hash, 64, in, inlen, 0, 0);
}
