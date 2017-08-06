#include "monocypher.h"


#ifdef ED25519_SHA512
    #include "rename_sha512.h"
    #define HASH rename_sha512
#else
    #define HASH crypto_blake2b
#endif
#define COMBINE1(x, y) x ## y
#define COMBINE2(x, y) COMBINE1(x, y)
#define HASH_CTX    COMBINE2(HASH, _ctx)
#define HASH_INIT   COMBINE2(HASH, _init)
#define HASH_UPDATE COMBINE2(HASH, _update)
#define HASH_FINAL  COMBINE2(HASH, _final)

typedef struct {
    HASH_CTX ctx;
} ed25519_hash_context;

void ed25519_hash_init(ed25519_hash_context *ctx)
{
    HASH_INIT(&(ctx->ctx));
}
void ed25519_hash_update(ed25519_hash_context *ctx, const uint8_t *in, size_t inlen)
{
    HASH_UPDATE(&(ctx->ctx), in, inlen);
}
void ed25519_hash_final(ed25519_hash_context *ctx, uint8_t *hash)
{
    HASH_FINAL(&(ctx->ctx), hash);
}
void ed25519_hash(uint8_t *hash, const uint8_t *in, size_t inlen)
{
    HASH(hash, in, inlen);
}


