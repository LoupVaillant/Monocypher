// ripped off from the reference implentation in RFC 7693

#include "blake2b.h"

// Cyclic right rotation.
static uint64_t
rotr64(uint64_t x, uint64_t y)
{
    return (x >> y) ^ (x << (64 - y));
}

static uint64_t
load64_le(uint8_t *s)
{
    // portable, slow way
    return
        ((uint64_t)s[0]      ) ^
        ((uint64_t)s[1] <<  8) ^
        ((uint64_t)s[2] << 16) ^
        ((uint64_t)s[3] << 24) ^
        ((uint64_t)s[4] << 32) ^
        ((uint64_t)s[5] << 40) ^
        ((uint64_t)s[6] << 48) ^
        ((uint64_t)s[7] << 56);
}

// Initialization Vector.
static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// increment a 128-bit "word".
static void
incr(uint64_t x[2], uint64_t y)
{
    x[0] += y;                 // increment the low word
    if (x[0] < y) { x[1]++; }  // handle overflow
}

static void
blake2b_compress(crypto_blake2b_ctx *ctx, _Bool last_block)
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

    // init work variables (before shuffling them)
    uint64_t v[16];
    for (int i = 0; i < 8; i++) {
        v[i    ] = ctx->hash[i];
        v[i + 8] = blake2b_iv[i];
    }
    v[12] ^= ctx->input_size[0]; // low 64 bits of offset
    v[13] ^= ctx->input_size[1]; // high 64 bits
    if (last_block) { v[14] = ~v[14]; }

    // load the input buffer
    uint64_t m[16];
    for (int i = 0; i < 16; i++) {
        m[i] = load64_le(&ctx->buf[i * 8]);
    }

    // shuffle the work variables with the 12 rounds
    for (int i = 0; i < 12; i++) {
#define B2B_G(a, b, c, d, x, y)                                    \
        v[a] += v[b] + x;  v[d] ^= v[a];  v[d] = rotr64(v[d], 32); \
        v[c] += v[d]    ;  v[b] ^= v[c];  v[b] = rotr64(v[b], 24); \
        v[a] += v[b] + y;  v[d] ^= v[a];  v[d] = rotr64(v[d], 16); \
        v[c] += v[d]    ;  v[b] ^= v[c];  v[b] = rotr64(v[b], 63)

        B2B_G( 0, 4,  8, 12, m[sigma[i][ 0]], m[sigma[i][ 1]]);
        B2B_G( 1, 5,  9, 13, m[sigma[i][ 2]], m[sigma[i][ 3]]);
        B2B_G( 2, 6, 10, 14, m[sigma[i][ 4]], m[sigma[i][ 5]]);
        B2B_G( 3, 7, 11, 15, m[sigma[i][ 6]], m[sigma[i][ 7]]);
        B2B_G( 0, 5, 10, 15, m[sigma[i][ 8]], m[sigma[i][ 9]]);
        B2B_G( 1, 6, 11, 12, m[sigma[i][10]], m[sigma[i][11]]);
        B2B_G( 2, 7,  8, 13, m[sigma[i][12]], m[sigma[i][13]]);
        B2B_G( 3, 4,  9, 14, m[sigma[i][14]], m[sigma[i][15]]);
    }

    // accumulate the work variables into the hash
    for(int i = 0; i < 8; i++) {
        ctx->hash[i] ^= v[i] ^ v[i + 8];
    }
}

void
crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t outlen,
                            const uint8_t      *key, size_t keylen)
{
    // Initial hash == initialization vector...
    for (int i = 0; i < 8; i++) {
        ctx->hash[i] = blake2b_iv[i];
    }
    ctx->hash[0]      ^= 0x01010000 ^ (keylen << 8) ^ outlen;  // ...mostly
    ctx->input_size[0] = 0;       // input count low word
    ctx->input_size[1] = 0;       // input count high word
    ctx->c             = 0;       // pointer within buffer
    ctx->output_size   = outlen;  // size of the final hash

    // If there's a key, put it in the first block, then pad with zeroes
    if (keylen > 0) {
        for (size_t i = 0     ; i < keylen; i++) { ctx->buf[i] = key[i]; }
        for (size_t i = keylen; i < 128   ; i++) { ctx->buf[i] = 0;      }
        ctx->c = 128; // mark the block as used
    }
}

void
crypto_blake2b_init(crypto_blake2b_ctx *ctx)
{
    crypto_blake2b_general_init(ctx, 64, 0, 0);
}

void
crypto_blake2b_update(crypto_blake2b_ctx *ctx, const uint8_t *in, size_t inlen)
{
    for (size_t i = 0; i < inlen; i++) {
        // If the buffer is full, increment the counters and
        // add (compress) the current buffer to the hash
        if (ctx->c == 128) {
            ctx->c = 0;
            incr(ctx->input_size, 128);
            blake2b_compress(ctx, 0); // not last time -> 0
        }
        // By now the buffer is not full.  We add one input byte.
        ctx->buf[ctx->c] = in[i];
        ctx->c++;
    }
}

void
crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *out)
{
    // update input size, pad then compress the buffer
    incr(ctx->input_size, ctx->c);
    for (int i = ctx->c; i < 128; i++) { ctx->buf[i] = 0; }
    blake2b_compress(ctx, 1); // last time -> 1

    // copy the hash in the output (little endian of course)
    for (int i = 0; i < ctx->output_size; i++) {
        out[i] = (ctx->hash[i / 8] >> (8 * (i & 7))) & 0xFF;
    }
}

void
crypto_blake2b_general(      uint8_t*out, size_t outlen,
                       const uint8_t*key, size_t keylen,
                       const uint8_t*in,  size_t inlen)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, outlen, key, keylen);
    crypto_blake2b_update(&ctx, in, inlen);
    crypto_blake2b_final(&ctx, out);
}

void
crypto_blake2b(uint8_t *out, const uint8_t *in, size_t inlen)
{
    crypto_blake2b_general(out, 64, 0, 0, in, inlen);
}
