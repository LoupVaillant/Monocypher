
// copied from monocypher
typedef struct {
    uint8_t  buf[128];      // input buffer
    uint64_t hash[8];       // chained state
    uint64_t input_size[2]; // total number of bytes
    uint8_t  c;             // pointer for buf[]
    uint8_t  output_size;   // digest size
} crypto_blake2b_ctx;

void crypto_blake2b_init(crypto_blake2b_ctx *ctx);
void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const uint8_t *in, size_t in_size);
void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *out);
void crypto_blake2b(uint8_t out[64], const uint8_t *in, size_t in_size);

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


