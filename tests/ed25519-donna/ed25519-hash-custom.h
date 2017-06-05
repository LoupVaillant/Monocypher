#include "monocypher.h"

typedef struct {
    crypto_blake2b_ctx ctx;
} ed25519_hash_context;

void ed25519_hash_init(ed25519_hash_context *ctx)
{
    crypto_blake2b_init(&(ctx->ctx));
}
void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen)
{
    crypto_blake2b_update(&(ctx->ctx), in, inlen);
}
void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash)
{
    crypto_blake2b_final(&(ctx->ctx), hash);
}
void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen)
{
    crypto_blake2b(hash, in, inlen);
}


