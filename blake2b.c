// ripped off from the reference implentation in RFC 7693

#include "blake2b.h"

// Cyclic right rotation.
static uint64_t
rotr64(uint64_t x, uint64_t y)
{
    return (x >> y) ^ (x << (64 - y));
}

static uint64_t
load64_le(uint8_t *p)
{
    return
        ( (uint64_t) (p)[0]       ) ^
        (((uint64_t) (p)[1]) <<  8) ^
        (((uint64_t) (p)[2]) << 16) ^
        (((uint64_t) (p)[3]) << 24) ^
        (((uint64_t) (p)[4]) << 32) ^
        (((uint64_t) (p)[5]) << 40) ^
        (((uint64_t) (p)[6]) << 48) ^
        (((uint64_t) (p)[7]) << 56);
}

// Initialization Vector.
static const uint64_t blake2b_iv[8] = {
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

// Compression function. "last" flag indicates last block.
static void
blake2b_compress(crypto_blake2b_ctx *ctx, int last)
{
    static const uint8_t sigma[12][16] = {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    };
    int i;
    uint64_t v[16], m[16];

    for (i = 0; i < 8; i++) {           // init work variables
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_iv[i];
    }
    v[12] ^= ctx->t[0];                 // low 64 bits of offset
    v[13] ^= ctx->t[1];                 // high 64 bits
    if (last)                           // last block flag set ?
        v[14] = ~v[14];

    for (i = 0; i < 16; i++) {          // get little-endian words
        m[i] = load64_le(&ctx->b[8 * i]);
    }
    for (i = 0; i < 12; i++) {          // twelve rounds
#define B2B_G(a, b, c, d, x, y)                                   \
        v[a] += v[b] + x;   v[d] = rotr64(v[d] ^ v[a], 32);       \
        v[c] += v[d]    ;   v[b] = rotr64(v[b] ^ v[c], 24);       \
        v[a] += v[b] + y;   v[d] = rotr64(v[d] ^ v[a], 16);       \
        v[c] += v[d]    ;   v[b] = rotr64(v[b] ^ v[c], 63)

        B2B_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
        B2B_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
        B2B_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
        B2B_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
        B2B_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
        B2B_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
        B2B_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
        B2B_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
    }

    for( i = 0; i < 8; ++i ) {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

void
crypto_blake2b_general_init(crypto_blake2b_ctx *ctx,
                            size_t              outlen,
                            const uint8_t      *key,
                            size_t              keylen)
{

    for (size_t i = 0; i < 8; i++) {      // state, "param block"
        ctx->h[i] = blake2b_iv[i];
    }

    ctx->h[0]  ^= 0x01010000 ^ (keylen << 8) ^ outlen;
    ctx->t[0]   = 0;                        // input count low word
    ctx->t[1]   = 0;                        // input count high word
    ctx->c      = 0;                        // pointer within buffer
    ctx->outlen = outlen;
    for (size_t i = keylen; i < 128; i++) { // zero input block
        ctx->b[i] = 0;
    }
    if (keylen > 0) {
        crypto_blake2b_update(ctx, key, keylen);
        ctx->c = 128;                       // at the end
    }
}

void
crypto_blake2b_init(crypto_blake2b_ctx *ctx)
{
    crypto_blake2b_general_init(ctx, 64, 0, 0);
}

void
crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                      const uint8_t *in, size_t inlen)
{
    size_t i;

    for (i = 0; i < inlen; i++) {
        if (ctx->c == 128) {            // buffer full ?
            ctx->t[0] += ctx->c;        // add counters
            if (ctx->t[0] < ctx->c) {   // carry overflow ?
                ctx->t[1]++;            // high word
            }
            blake2b_compress(ctx, 0);   // compress (not last)
            ctx->c = 0;                 // counter to zero
        }
        ctx->b[ctx->c++] = ((const uint8_t *) in)[i];
    }
}

void
crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *out)
{
    size_t i;

    ctx->t[0] += ctx->c;                // mark last block offset
    if (ctx->t[0] < ctx->c)             // carry overflow
        ctx->t[1]++;                    // high word

    while (ctx->c < 128)                // fill up with zeros
        ctx->b[ctx->c++] = 0;
    blake2b_compress(ctx, 1);           // final block flag = 1

    // little endian convert and store
    for (i = 0; i < ctx->outlen; i++) {
        ((uint8_t *) out)[i] =
            (ctx->h[i >> 3] >> (8 * (i & 7))) & 0xFF;
    }
}

void
crypto_general_blake2b(      uint8_t*out, size_t outlen,
                       const uint8_t*key, size_t keylen,
                       const uint8_t*in, size_t inlen)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, outlen, key, keylen);
    crypto_blake2b_update(&ctx, in, inlen);
    crypto_blake2b_final(&ctx, out);
}

void
crypto_blake2b(uint8_t *out, const uint8_t *in, size_t inlen)
{
    crypto_general_blake2b(out, 64, 0, 0, in, inlen);
}
