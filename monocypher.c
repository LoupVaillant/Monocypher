#include "monocypher.h"

static uint32_t load32_le(const uint8_t s[4])
{
    return s[0]
        | (s[1] <<  8)
        | (s[2] << 16)
        | (s[3] << 24);
}

static void store32_le(uint8_t output[4], uint32_t input)
{
    output[0] =  input        & 0xff;
    output[1] = (input >>  8) & 0xff;
    output[2] = (input >> 16) & 0xff;
    output[3] = (input >> 24) & 0xff;
}

static uint64_t rotr64(uint64_t x, uint64_t y)
{
    return (x >> y) ^ (x << (64 - y));
}

static uint64_t load64_le(const uint8_t s[8])
{
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

static void store64_le(uint8_t output[8], uint64_t input)
{
    output[0] =  input        & 0xff;
    output[1] = (input >>  8) & 0xff;
    output[2] = (input >> 16) & 0xff;
    output[3] = (input >> 24) & 0xff;
    output[4] = (input >> 32) & 0xff;
    output[5] = (input >> 40) & 0xff;
    output[6] = (input >> 48) & 0xff;
    output[7] = (input >> 56) & 0xff;
}

static void
chacha20_rounds(uint32_t out[16], const uint32_t in[16])
{
    for (int i = 0; i < 16; i++)
        out[i] = in[i];

    for (int i = 0; i < 10; i++) { // 20 rounds, 2 rounds per loop.
#define ROT_L32(x, n) x = (x << n) | (x >> (32 - n))
#define QUARTERROUND(a, b, c, d)           \
        a += b;  d ^= a;  ROT_L32(d, 16);  \
        c += d;  b ^= c;  ROT_L32(b, 12);  \
        a += b;  d ^= a;  ROT_L32(d,  8);  \
        c += d;  b ^= c;  ROT_L32(b,  7)

        QUARTERROUND(out[0], out[4], out[ 8], out[12]); // column 0
        QUARTERROUND(out[1], out[5], out[ 9], out[13]); // column 1
        QUARTERROUND(out[2], out[6], out[10], out[14]); // column 2
        QUARTERROUND(out[3], out[7], out[11], out[15]); // column 3
        QUARTERROUND(out[0], out[5], out[10], out[15]); // diagonal 1
        QUARTERROUND(out[1], out[6], out[11], out[12]); // diagonal 2
        QUARTERROUND(out[2], out[7], out[ 8], out[13]); // diagonal 3
        QUARTERROUND(out[3], out[4], out[ 9], out[14]); // diagonal 4
    }
}

static void
chacha20_init_key(crypto_chacha_ctx *ctx, const uint8_t key[32])
{
    // constant
    ctx->input[0]   = load32_le((uint8_t*)"expa");
    ctx->input[1]   = load32_le((uint8_t*)"nd 3");
    ctx->input[2]   = load32_le((uint8_t*)"2-by");
    ctx->input[3]   = load32_le((uint8_t*)"te k");
    // key
    for (int i = 0; i < 8; i++)
        ctx->input[i + 4] = load32_le(key + i*4);
    // pool index (the random pool starts empty)
    ctx->pool_index = 64;
}

void
crypto_chacha20_H(uint8_t       out[32],
                  const uint8_t key[32],
                  const uint8_t in [16])
{
    crypto_chacha_ctx ctx;
    chacha20_init_key(&ctx, key);
    for (int i = 0; i < 4; i++)
        ctx.input[i + 12] = load32_le(in + i*4);

    uint32_t buffer[16];
    chacha20_rounds(buffer, ctx.input);
    // prevents reversal of the rounds by revealing only half of the buffer.
    for (int i = 0; i < 4; i++) {
        store32_le(out      + i*4, buffer[i     ]); // constant
        store32_le(out + 16 + i*4, buffer[i + 12]); // counter and nonce
    }
}

void
crypto_chacha20_init(crypto_chacha_ctx *ctx,
                     const uint8_t      key[32],
                     const uint8_t      nonce[8])
{
    chacha20_init_key(ctx, key  );         // key
    ctx->input[12] = 0;                    // counter
    ctx->input[13] = 0;                    // counter
    ctx->input[14] = load32_le(nonce + 0); // nonce
    ctx->input[15] = load32_le(nonce + 4); // nonce
}

void
crypto_chacha20_Xinit(crypto_chacha_ctx *ctx,
                      const uint8_t      key[32],
                      const uint8_t      nonce[24])
{
    uint8_t derived_key[32];
    crypto_chacha20_H(derived_key, key, nonce);
    crypto_chacha20_init(ctx, derived_key, nonce + 16);
}

void
crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                        const uint8_t     *plain_text,
                        uint8_t           *cipher_text,
                        size_t             message_size)
{
    for (size_t i = 0; i < message_size; i++) {
        // refill the pool if empty
        if (ctx->pool_index == 64) {
            // fill the pool
            uint32_t buffer[16];
            chacha20_rounds(buffer, ctx->input);
            for (int i = 0; i < 16; i++)
                store32_le(ctx->random_pool + i*4, buffer[i] + ctx->input[i]);
            // update the counters
            ctx->pool_index = 0;
            ctx->input[12]++;
            if (!ctx->input[12])
                ctx->input[13]++;
        }
        // use the pool for encryption (or random stream)
        cipher_text[i] =
            (plain_text == 0 ? 0 : plain_text[i])
            ^ ctx->random_pool[ctx->pool_index];
        ctx->pool_index++;
    }
}

void
crypto_chacha20_random(crypto_chacha_ctx *ctx,
                       uint8_t           *cipher_text,
                       size_t             message_size)
{
    crypto_chacha20_encrypt(ctx, 0, cipher_text, message_size);
}



static void poly_load(uint32_t out[4], const uint8_t in[16])
{
    for (int i = 0; i < 4; i++)
        out[i] = load32_le(in + i*4);
}

static void poly_add(uint32_t out[5], const uint32_t a[5], const uint32_t b[5])
{
    uint64_t carry = 0;
    for (int i = 0; i < 5; i++) {
        carry  += (int64_t)(a[i]) + b[i];
        out[i]  = carry & 0xffffffff; // lower 32 bits right there.
        carry >>= 32;                 // retain the carry
    }
}

// h = (h + c) * r
static void poly_block(crypto_poly1305_ctx *ctx)
{
    // h + c, without carry propagation
    const uint64_t h0 = ctx->h[0] + (uint64_t)ctx->c[0];
    const uint64_t h1 = ctx->h[1] + (uint64_t)ctx->c[1];
    const uint64_t h2 = ctx->h[2] + (uint64_t)ctx->c[2];
    const uint64_t h3 = ctx->h[3] + (uint64_t)ctx->c[3];
    const uint64_t h4 = ctx->h[4] + (uint64_t)ctx->c[4];

    // Local all the things!
    const uint64_t r0 = ctx->r[0];
    const uint64_t r1 = ctx->r[1];
    const uint64_t r2 = ctx->r[2];
    const uint64_t r3 = ctx->r[3];
    const uint64_t rr0 = (ctx->r[0] >> 2) * 5; // lose 2 bottom bits...
    const uint64_t rr1 = (ctx->r[1] >> 2) * 5; // 2 bottom bits already cleared
    const uint64_t rr2 = (ctx->r[2] >> 2) * 5; // 2 bottom bits already cleared
    const uint64_t rr3 = (ctx->r[3] >> 2) * 5; // 2 bottom bits already cleared

    // (h + c) * r, without carry propagation
    const uint64_t x0 = h0*r0 + h1*rr3 + h2*rr2 + h3*rr1 + h4*rr0;
    const uint64_t x1 = h0*r1 + h1*r0  + h2*rr3 + h3*rr2 + h4*rr1;
    const uint64_t x2 = h0*r2 + h1*r1  + h2*r0  + h3*rr3 + h4*rr2;
    const uint64_t x3 = h0*r3 + h1*r2  + h2*r1  + h3*r0  + h4*rr3;
    const uint64_t x4 = h4 * (r0 & 3); // ...recover those 2 bits

    // carry propagation, put ctx->h under 2^130
    const uint64_t msb = x4 + (x3 >> 32);
    uint64_t       u   = (msb >> 2) * 5; // lose 2 bottom bits...
    u += (x0 & 0xffffffff)             ;  ctx->h[0] = u & 0xffffffff;  u >>= 32;
    u += (x1 & 0xffffffff) + (x0 >> 32);  ctx->h[1] = u & 0xffffffff;  u >>= 32;
    u += (x2 & 0xffffffff) + (x1 >> 32);  ctx->h[2] = u & 0xffffffff;  u >>= 32;
    u += (x3 & 0xffffffff) + (x2 >> 32);  ctx->h[3] = u & 0xffffffff;  u >>= 32;
    u += msb & 3 /* ...recover them */ ;  ctx->h[4] = u;
}

// (re-)initializes the input counter and input buffer
static void poly_clear_c(crypto_poly1305_ctx *ctx)
{
    for (int i = 0; i < 4; i++)
        ctx->c[i] = 0;
    ctx->c_index = 0;
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32])
{
    // initial h: zero
    for (int i =  0; i < 5; i++)
        ctx->h [i] = 0;
    // initial r: first half of the key, minus a few bits
    poly_load(ctx->r, key);
    ctx->r[0] &= 0x0fffffff; // clear top 4 bits
    ctx->r[1] &= 0x0ffffffc; // clear top 4 & bottom 2 bits
    ctx->r[2] &= 0x0ffffffc; // clear top 4 & bottom 2 bits
    ctx->r[3] &= 0x0ffffffc; // clear top 4 & bottom 2 bits
    ctx->c[4]  = 1;
    // second half of the key, saved for later
    poly_load(ctx->pad, key + 16);
    ctx->pad[4] = 0;
    // buffer and counter
    poly_clear_c(ctx);
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *m, size_t bytes)
{
    while (bytes > 0) {
        if (ctx->c_index == 16) {
            poly_block(ctx);
            poly_clear_c(ctx);
        }
        // feed the input buffer
        ctx->c[ctx->c_index / 4] |= *m << ((ctx->c_index % 4) * 8);
        ctx->c_index++;
        m++;
        bytes--;
    }
}

void crypto_poly1305_finish(crypto_poly1305_ctx *ctx, uint8_t mac[16])
{
    // move the final 1 according to remaining input length
    ctx->c[4] = 0;
    ctx->c[ctx->c_index / 4] |= 1 << ((ctx->c_index % 4) * 8);
    // one last hash update...
    poly_block(ctx);
    // ... this time with full modular reduction
    // We only need to conditionally subtract 2^130-5,
    // using bit twidling to prevent timing attacks.
    static const uint32_t minus_p[5] = { 5, 0, 0, 0, 0xfffffffc };
    uint32_t h_minus_p[5];
    poly_add(h_minus_p, ctx->h, minus_p);
    uint32_t negative = ~(-(h_minus_p[4] >> 31)); // 0 or -1 (2's complement)
    for (int i = 0; i < 5; i++) {
        ctx->h[i] ^= negative & (ctx->h[i] ^ h_minus_p[i]);
    }
    // Add the secret pad to the final hash before output
    poly_add(ctx->h, ctx->h, ctx->pad);
    for (int i = 0; i < 4; i++)
        store32_le(mac + i*4, ctx->h[i]);
}

void crypto_poly1305_auth(uint8_t mac[16], const uint8_t *m,
                          size_t  m_size , const uint8_t  key[32])
{
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, key);
    crypto_poly1305_update(&ctx, m, m_size);
    crypto_poly1305_finish(&ctx, mac);
}

int crypto_memcmp_16(const uint8_t mac1[16], const uint8_t mac2[16])
{
    unsigned diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (mac1[i] ^ mac2[i]);
    }
    return diff;
}
// ripped off from the reference implentation in RFC 7693




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
crypto_blake2b(uint8_t out[64], const uint8_t *in, size_t inlen)
{
    crypto_blake2b_general(out, 64, 0, 0, in, inlen);
}


/////////////////
/// Utilities ///
/////////////////


static uint32_t
min(uint32_t a, uint32_t b)
{
    return a <= b ? a : b;
}

// updates a blake2 hash with a 32 bit word, little endian.
static void
blake_update_32(crypto_blake2b_ctx *ctx, uint32_t input)
{
    uint8_t buf[4];
    store32_le(buf, input);
    crypto_blake2b_update(ctx, buf, 4);
}

//////////////////
// Argon2 block //
//////////////////
typedef struct block {
    uint64_t a[128]; // 1024 octets in 128 64-bit words
} block;

static void
load_block(block *b, const uint8_t bytes[1024])
{
    for (int i = 0; i < 128; i++) {
        b->a[i] = load64_le(bytes + i * 8);
    }
}

static void
store_block(uint8_t bytes[1024], const block *b)
{
    for (int i = 0; i < 128; i++) {
        store64_le(bytes + i * 8, b->a[i]);
    }
}

static void
copy_block(block *out, const block *in)
{
    for (int i = 0; i < 128; i++) {
        out->a[i] = in->a[i];
    }
}

static void
xor_block(block *out, const block *in)
{
    for (int i = 0; i < 128; i++) {
        out->a[i] ^= in->a[i];
    }
}

////////////////////
// Argon2i proper //
////////////////////

// Hash with a virtually unlimited digest size.
// Doesn't extract more entropy than the base hash function.
// Mainly used for filling a whole kilobyte block with pseudo-random bytes.
static void
extended_hash(uint8_t       *digest, uint32_t digest_size,
              const uint8_t *input , uint32_t input_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, min(digest_size, 64), 0, 0);
    blake_update_32            (&ctx, digest_size);
    crypto_blake2b_update      (&ctx, input, input_size);
    crypto_blake2b_final       (&ctx, digest);

    if (digest_size > 64) {
        // the conversion to u64 avoids integer overflow on
        // ludicrously big hash sizes.
        uint32_t r   = (((uint64_t)digest_size + 31) / 32) - 2;
        uint32_t i   =  1;
        uint32_t in  =  0;
        uint32_t out = 32;
        while (i < r) {
            // Input and output overlap.
            // This shouldn't be a problem.
            crypto_blake2b(digest + out, digest + in, 64);
            i   +=  1;
            in  += 32;
            out += 32;
        }
        crypto_blake2b_general(digest + out, digest_size - (32 * r),
                               0, 0, // no key
                               digest + in , 64);
    }
}

// Core of the compression function G.  Computes Z from R in place.
static void
g_rounds(block *work_block)
{
#define LSB(x) ((x) & 0xffffffff)
#define G(a, b, c, d)                                            \
    a += b + 2 * LSB(a) * LSB(b);  d ^= a;  d = rotr64(d, 32);   \
    c += d + 2 * LSB(c) * LSB(d);  b ^= c;  b = rotr64(b, 24);   \
    a += b + 2 * LSB(a) * LSB(b);  d ^= a;  d = rotr64(d, 16);   \
    c += d + 2 * LSB(c) * LSB(d);  b ^= c;  b = rotr64(b, 63)
#define ROUND(v0,  v1,  v2,  v3,  v4,  v5,  v6,  v7,    \
              v8,  v9, v10, v11, v12, v13, v14, v15)    \
    G(v0, v4,  v8, v12);  G(v1, v5,  v9, v13);          \
    G(v2, v6, v10, v14);  G(v3, v7, v11, v15);          \
    G(v0, v5, v10, v15);  G(v1, v6, v11, v12);          \
    G(v2, v7,  v8, v13);  G(v3, v4,  v9, v14)

    // column rounds (work_block = Q)
    for (int i = 0; i < 128; i += 16) {
        ROUND(work_block->a[i     ], work_block->a[i +  1],
              work_block->a[i +  2], work_block->a[i +  3],
              work_block->a[i +  4], work_block->a[i +  5],
              work_block->a[i +  6], work_block->a[i +  7],
              work_block->a[i +  8], work_block->a[i +  9],
              work_block->a[i + 10], work_block->a[i + 11],
              work_block->a[i + 12], work_block->a[i + 13],
              work_block->a[i + 14], work_block->a[i + 15]);
    }
    // row rounds (work_block = Z)
    for (int i = 0; i < 16; i += 2) {
        ROUND(work_block->a[i      ], work_block->a[i +   1],
              work_block->a[i +  16], work_block->a[i +  17],
              work_block->a[i +  32], work_block->a[i +  33],
              work_block->a[i +  48], work_block->a[i +  49],
              work_block->a[i +  64], work_block->a[i +  65],
              work_block->a[i +  80], work_block->a[i +  81],
              work_block->a[i +  96], work_block->a[i +  97],
              work_block->a[i + 112], work_block->a[i + 113]);
    }
}

// The compression function G
// may overwrite result completely  (xcopy == copy_block),
// or XOR result with the old block (xcopy ==  xor_block)
static void
binary_g(block *result, const block *x, const block *y,
         void (*xcopy) (block*, const block*))
{
    // put R = X ^ Y into tmp
    block tmp;
    copy_block(&tmp, x);
    xor_block (&tmp, y);

    xcopy(result, &tmp);     // save R (erase or xor the old block)
    g_rounds(&tmp);          // tmp = Z
    xor_block(result, &tmp); // result =  R ^ Z (or R ^ Z ^ old)
}

// unary version of the compression function.
// The missing argument is implied zero.
// Does the transformation in place.
static void
unary_g(block *work_block)
{
    // work_block == R
    block tmp;
    copy_block(&tmp, work_block); // tmp = R
    g_rounds(work_block);         // work_block = Z
    xor_block(work_block, &tmp);  // work_block = Z ^ R
}

typedef struct gidx_ctx {
    block    b;
    uint32_t pass_number;
    uint32_t slice_number;
    uint32_t nb_blocks;
    uint32_t nb_iterations;
    uint32_t ctr;
    uint32_t index;
} gidx_ctx;

static void
gidx_refresh(gidx_ctx *ctx)
{
    ctx->b.a[0] = ctx->pass_number;
    ctx->b.a[1] = 0;  // lane number (we have only one)
    ctx->b.a[2] = ctx->slice_number;
    ctx->b.a[3] = ctx->nb_blocks;
    ctx->b.a[4] = ctx->nb_iterations;
    ctx->b.a[5] = 1;  // type: Argon2i
    ctx->b.a[6] = ctx->ctr;
    // zero the rest of the block
    for (int i = 7; i < 128; i++) {
        ctx->b.a[i] = 0;
    }

    // Shuffle the block thus: ctx->b = G((G(ctx->b, zero)), zero)
    // Applies the G "square" function to get cheap pseudo-random numbers.
    unary_g(&(ctx->b));
    unary_g(&(ctx->b)); // square means apply it twice
}

static void
gidx_init(gidx_ctx *ctx,
          uint32_t pass_number,
          uint32_t slice_number,
          uint32_t nb_blocks,
          uint32_t nb_iterations)
{
    ctx->pass_number   = pass_number;
    ctx->slice_number  = slice_number;
    ctx->nb_blocks     = nb_blocks;
    ctx->nb_iterations = nb_iterations;
    ctx->ctr           = 1;   // not zero, surprisingly
    ctx->index         = pass_number == 0 && slice_number == 0 ? 2 : 0;
    gidx_refresh(ctx);
}

static uint32_t
gidx_next(gidx_ctx *ctx)
{
    // lazily creates the index block we need
    if (ctx->index == 128) {
        ctx->index = 0;
        ctx->ctr++;
        gidx_refresh(ctx);
    }
    // saves and increment the index
    uint32_t index = ctx->index;
    ctx->index++; // updates index for the next call

    // Computes the area size.
    // Pass 0 : all already finished segments plus already constructed
    //          blocks in this segment
    // Pass 1+: 3 last segments plus already constructed
    //          blocks in this segment.  THE SPEC SUGGESTS OTHERWISE.
    //          I CONFORM TO THE REFERENCE IMPLEMENTATION.
    _Bool    first_pass = ctx->pass_number == 0;
    uint32_t slice_size = ctx->nb_blocks / 4;
    uint32_t area_size  = ((first_pass ? ctx->slice_number : 3)
                           * slice_size + index - 1);

    // Computes the starting position of the reference area.
    // CONTRARY TO WHAT THE SPEC SUGGESTS, IT STARTS AT THE
    // NEXT SEGMENT, NOT THE NEXT BLOCK.
    uint32_t next_slice = (ctx->slice_number == 3
                           ? 0
                           : (ctx->slice_number + 1) * slice_size);
    uint32_t start_pos  = first_pass ? 0 : next_slice;

    // Generates the actual index from J1 (no need for J2, there's only one lane)
    uint64_t j1         = ctx->b.a[index] & 0xffffffff; // pseudo-random number
    uint64_t x          = (j1 * j1)       >> 32;
    uint64_t y          = (area_size * x) >> 32;
    uint64_t z          = area_size - 1 - y;
    return (start_pos + z) % ctx->nb_blocks;
}

// Main algorithm
void
crypto_argon2i_hash(uint8_t       *tag,       uint32_t tag_size,
                    const uint8_t *password,  uint32_t password_size,
                    const uint8_t *salt,      uint32_t salt_size,
                    const uint8_t *key,       uint32_t key_size,
                    const uint8_t *ad,        uint32_t ad_size,
                    void *work_area,
                    uint32_t nb_blocks,
                    uint32_t nb_iterations)
{
    // work area seen as blocks (must be suitably aligned)
    block *blocks = work_area;
    {
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx);

        blake_update_32      (&ctx, 1            ); // p: number of threads
        blake_update_32      (&ctx, tag_size     );
        blake_update_32      (&ctx, nb_blocks    );
        blake_update_32      (&ctx, nb_iterations);
        blake_update_32      (&ctx, 0x13         ); // v: version number
        blake_update_32      (&ctx, 1            ); // y: Argon2i
        blake_update_32      (&ctx,           password_size);
        crypto_blake2b_update(&ctx, password, password_size);
        blake_update_32      (&ctx,           salt_size);
        crypto_blake2b_update(&ctx, salt,     salt_size);
        blake_update_32      (&ctx,           key_size);
        crypto_blake2b_update(&ctx, key,      key_size);
        blake_update_32      (&ctx,           ad_size);
        crypto_blake2b_update(&ctx, ad,       ad_size);

        uint8_t initial_hash[72]; // 64 bytes plus 2 words for future hashes
        crypto_blake2b_final(&ctx, initial_hash);

        // fill first 2 blocks
        block   tmp_block;
        uint8_t hash_area[1024];
        store32_le(initial_hash + 64, 0); // first  additional word
        store32_le(initial_hash + 68, 0); // second additional word
        extended_hash(hash_area, 1024, initial_hash, 72);
        load_block(&tmp_block, hash_area);
        copy_block(blocks, &tmp_block);

        store32_le(initial_hash + 64, 1); // slight modification
        extended_hash(hash_area, 1024, initial_hash, 72);
        load_block(&tmp_block, hash_area);
        copy_block(blocks + 1, &tmp_block);
    }

    // Actual number of blocks
    nb_blocks -= nb_blocks % 4; // round down to 4 p (p == 1 thread)
    const uint32_t segment_size = nb_blocks / 4;

    // fill (then re-fill) the rest of the blocks
    for (uint32_t pass_number = 0; pass_number < nb_iterations; pass_number++) {
        _Bool     first_pass  = pass_number == 0;
        // Simple copy on pass 0, XOR instead of overwrite on subsequent passes
        void (*xcopy) (block*, const block*) = first_pass ?copy_block :xor_block;

        for (int segment = 0; segment < 4; segment++ ) {

            gidx_ctx ctx;
            gidx_init(&ctx, pass_number, segment, nb_blocks, nb_iterations);

            // On the first segment of the first pass,
            // blocks 0 and 1 are already filled.
            // We use the offset to skip them.
            uint32_t offset = first_pass && segment == 0 ? 2 : 0;
            // current, reference, and previous are block indices
            for (uint32_t current =  segment      * segment_size + offset;
                 current          < (segment + 1) * segment_size;
                 current++) {
                uint32_t previous  = current == 0 ? nb_blocks - 1 : current - 1;
                uint32_t reference = gidx_next(&ctx);
                binary_g(blocks + current,
                         blocks + previous,
                         blocks + reference,
                         xcopy);
            }
        }
    }
    // hash the very last block with H' into the output tag
    uint8_t final_block[1024];
    store_block(final_block, blocks + (nb_blocks - 1));
    extended_hash(tag, tag_size, final_block, 1024);
}

void
crypto_argon2i(uint8_t        tag[32],
               const uint8_t *password,  uint32_t password_size,
               const uint8_t *salt,      uint32_t salt_size,
               void    *work_area,
               uint32_t nb_blocks,
               uint32_t nb_iterations)
{
    crypto_argon2i_hash(tag     , 32,
                        password, password_size,
                        salt    , salt_size,
                        0, 0, 0, 0,
                        work_area, nb_blocks, nb_iterations);
}

// Taken from TweetNaCl


#define FOR(i, start, end) for (size_t i = start; i < end; i++)
#define sv static void
typedef int64_t gf[16];

static const uint8_t _0[16];
static const uint8_t _9[32] = { 9 };
static const gf _121665 = { 0xdb41, 1 };

sv car_25519(gf o)
{
    FOR(i, 0, 16) {
        o[i]              += 1LL  << 16;
        int64_t c          = o[i] >> 16;
        o[(i+1) * (i<15)] += c - 1 + (37 * (c-1) * (i==15));
        o[i]              -= c << 16;
    }
}

sv sel_25519(gf p, gf q, int b)
{
    int64_t c = ~(b-1);
    FOR(i, 0, 16) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i]     ^= t;
        q[i]     ^= t;
    }
}

sv pack_25519(uint8_t *o, const gf n)
{
    gf t;
    FOR(i, 0, 16) t[i] = n[i];
    car_25519(t);
    car_25519(t);
    car_25519(t);
    FOR(j, 0, 2) {
        gf m;
        m[0] = t[0] - 0xffed;
        FOR(i, 1, 15) {
            m[i  ]  = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15]  = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b  = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel_25519(t, m, 1-b);
    }
    FOR(i, 0, 16) {
        o[2*i    ] = t[i] & 0xff;
        o[2*i + 1] = t[i] >> 8;
    }
}

sv unpack_25519(gf o, const uint8_t *n)
{
    FOR(i, 0, 16) o[i] = n[2*i] + ((int64_t)n[2*i + 1] << 8);
    o[15] &= 0x7fff;
}

sv A(gf o, const gf a, const gf b)
{
    FOR(i, 0, 16) o[i] = a[i] + b[i];
}

sv Z(gf o, const gf a, const gf b)
{
    FOR(i, 0, 16) o[i] = a[i] - b[i];
}

sv M(gf o, const gf a, const gf b)
{
    int64_t t[31];
    FOR(i, 0, 31) t[i] = 0;
    FOR(i, 0, 16) FOR(j, 0, 16) t[i+j] += a[i] * b[j];
    FOR(i, 0, 15) t[i] += 38 * t[i+16];
    FOR(i, 0, 16) o[i] = t[i];
    car_25519(o);
    car_25519(o);
}

sv S(gf o,const gf a)
{
    M(o, a, a);
}

sv inv_25519(gf o,const gf i)
{
    gf c;
    FOR(a, 0, 16) c[a] = i[a];
    for(int a = 253; a >= 0; a--) {
        S(c, c);
        if(a != 2 && a != 4)
            M(c, c, i);
    }
    FOR(a, 0, 16) o[a] = c[a];
}

void crypto_x25519(uint8_t q[32], const uint8_t n[32], const uint8_t p[32])
{
    uint8_t z[32];
    int64_t x[80];
    int64_t r;
    gf a, b, c, d, e, f;
    FOR(i, 0, 31) z[i] = n[i];
    z[31]  = (n[31] & 127) | 64;
    z[0 ] &= 248;
    unpack_25519(x, p);
    FOR(i, 0, 16) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for(int i = 254; i>=0; i--) {
        r = (z[i>>3] >> (i & 7)) & 1;
        sel_25519(a, b, r);
        sel_25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, _121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel_25519(a, b, r);
        sel_25519(c, d, r);
    }
    FOR(i, 0, 16) {
        x[i+16] = a[i];
        x[i+32] = c[i];
        x[i+48] = b[i];
        x[i+64] = d[i];
    }
    inv_25519(x+32, x+32);
    M(x+16, x+16, x+32);
    pack_25519(q, x+16);
}

void crypto_x25519_base(uint8_t q[32], const uint8_t n[32])
{
    crypto_x25519(q, n, _9);
}
// Taken from TweetNaCl.
// I tried the ref10 implementation, but that was too damn big


#define FOR(i, start, end) for (size_t i = start; i < end; i++)
#define sv static void
#define sc static const

typedef uint8_t   u8;
typedef int64_t  i64;
typedef uint64_t u64;
typedef i64 gf[16];

sc gf gf0;
sc gf gf1 = { 1 };
sc gf  D  = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
              0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
sc gf  D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
              0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
sc gf  X  = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
              0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
sc gf  Y  = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
              0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
sc gf  I  = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
              0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

sc u64 L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };

sv set_25519(gf r, const gf a) { FOR(i, 0, 16) r[i] = a[i]; }

static u8 par_25519(const gf a)
{
    u8 d[32];
    pack_25519(d, a);
    return d[0] & 1;
}

sv pow2523(gf o,const gf i)
{
    gf c;
    FOR(a, 0, 16) c[a] = i[a];
    for(int a = 250; a >= 0; a--) {
        S(c, c);
        if(a != 1) M(c, c, i);
    }
    FOR(a, 0, 16) o[a] = c[a];
}

static int vn(const u8 *x, const u8 *y, size_t n)
{
  uint32_t d = 0;
  FOR(i, 0, n) d |= x[i] ^ y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

static int neq_25519(const gf a, const gf b)
{
    u8 c[32],d[32];
    pack_25519(c, a);
    pack_25519(d, b);
    return vn(c, d, 32);
}

sv add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

sv cswap(gf p[4], gf q[4], u8 b)
{
    FOR(i, 0, 4)
        sel_25519(p[i],q[i],b);
}

sv pack(u8 *r, gf p[4])
{
    gf tx, ty, zi;
    inv_25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack_25519(r, ty);
    r[31] ^= par_25519(tx) << 7;
}

sv scalarmult(gf p[4], gf q[4], const u8 *s)
{
    set_25519(p[0], gf0);
    set_25519(p[1], gf1);
    set_25519(p[2], gf1);
    set_25519(p[3], gf0);
    for (int i = 255; i >= 0; i--) {
        u8 b = (s[i/8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

sv scalarbase(gf p[4], const u8 *s)
{
    gf q[4];
    set_25519(q[0], X);
    set_25519(q[1], Y);
    set_25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

sv modL(u8 *r, i64 x[64])
{
    i64 i, j;
    for (i = 63;i >= 32;--i) {
        i64 carry = 0;
        for (j = i - 32;j < i - 12;++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    i64 carry = 0;
    FOR(j, 0, 32) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    FOR(j, 0, 32) x[j] -= carry * L[j];
    FOR(i, 0, 32) {
        x[i+1] += x[i] >> 8;
        r[i  ]  = x[i] & 255;
    }
}

sv reduce(u8 r[64])
{
    i64 x[64];
    FOR(i, 0, 64) x[i] = (u64) r[i];
    FOR(i, 0, 64) r[i] = 0;
    modL(r, x);
}

static int unpackneg(gf r[4],const u8 p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    set_25519(r[2], gf1);
    unpack_25519(r[1], p);
    S(num,r [1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq_25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq_25519(chk, num)) return -1;

    if (par_25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

    M(r[3], r[0], r[1]);
    return 0;
}

#ifdef ED25519_SHA512
    #include "sha512.h"
    #define HASH crypto_sha512
#else
    #define HASH crypto_blake2b
#endif

#define COMBINE1(x, y) x ## y
#define COMBINE2(x, y) COMBINE1(x, y)
#define HASH_CTX    COMBINE2(HASH, _ctx)
#define HASH_INIT   COMBINE2(HASH, _init)
#define HASH_UPDATE COMBINE2(HASH, _update)
#define HASH_FINAL  COMBINE2(HASH, _final)

// hash function interface
// Typical uses: sha512 for tests vectors, blake2b for production.
void HASH_INIT  (HASH_CTX *ctx);
void HASH_UPDATE(HASH_CTX *ctx, const u8 *in, size_t inlen);
void HASH_FINAL (HASH_CTX *ctx, u8 hash[64]);
void HASH(u8 hash[64], const u8 *in, size_t inlen);

sv hash_k(u8 k[64], const u8 R[32], const u8 A[32], const u8 *M, size_t M_size)
{
    HASH_CTX ctx;
    HASH_INIT  (&ctx);
    HASH_UPDATE(&ctx, R , 32    );
    HASH_UPDATE(&ctx, A , 32    );
    HASH_UPDATE(&ctx, M , M_size);
    HASH_FINAL (&ctx, k);
    reduce(k);
}

void crypto_ed25519_public_key(uint8_t        public_key[32],
                               const uint8_t  secret_key[32])
{
    // hash the private key, turn the hash into a scalar
    u8 a[64];
    HASH(a, secret_key, 32);
    a[ 0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    // the public key is the packed form of the point aB (B == basepoint)
    gf aB[4];
    scalarbase(aB, a);
    pack(public_key, aB);
}

void crypto_ed25519_sign(uint8_t        signature[64],
                         const uint8_t  secret_key[32],
                         const uint8_t *message,
                         size_t         message_size)
{
    u8 h[64];
    u8 *a      = h;       // secret scalar
    u8 *prefix = h + 32;  // prefix for nonce generation
    HASH(h, secret_key, 32);

    // build public key from secret key
    a[ 0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    gf aB[4];
    scalarbase(aB, a);
    u8 public_key[32];
    pack(public_key, aB);

    // Constructs the "random" nonce from the secret key and message.
    // An actual random number would work just fine, and would save us
    // the trouble of hashing the message twice.  If we did that
    // however, the user could fuck it up and reuse the nonce.
    u8 r[64];
    HASH_CTX ctx;
    HASH_INIT  (&ctx);
    HASH_UPDATE(&ctx, prefix , 32          );
    HASH_UPDATE(&ctx, message, message_size);
    HASH_FINAL (&ctx, r);

    gf rB[4];
    reduce(r);
    scalarbase(rB, r);
    pack(signature, rB); // first half of the signature = "random" nonce

    u8 k[64];
    hash_k(k, signature, public_key, message, message_size);

    i64 s[64]; // s = r + k a
    FOR(i,  0, 32) s[i] = (u64) r[i];
    FOR(i, 32, 64) s[i] = 0;
    FOR(i, 0, 32) {
        FOR(j, 0, 32) {
            s[i+j] += k[i] * (u64) a[j];
        }
    }
    modL(signature + 32, s);  // second half of the signature = s
}

int crypto_ed25519_check(const uint8_t  signature[64],
                         const uint8_t  public_key[32],
                         const uint8_t *message,
                         size_t         message_size)
{
    gf aB[4];  if (unpackneg(aB, public_key)) return -1;   // -aB
    u8 k[64];  hash_k(k, signature, public_key, message, message_size);
    gf p[4];   scalarmult(p, aB, k);                       // p = -aB k
    gf sB[4];  scalarbase(sB, signature + 32); add(p, sB); // p = s - aB k
    u8 t[32];  pack(t, p);
    return vn(signature, t, 32); // R == s - aB k ? OK : fail
}

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

void crypto_lock_key(uint8_t       shared_key[32],
                     const uint8_t your_secret_key [32],
                     const uint8_t their_public_key[32])
{
    static const uint8_t _0[16];
    uint8_t shared_secret[32];
    crypto_x25519(shared_secret, your_secret_key, their_public_key);
    crypto_chacha20_H(shared_key, shared_secret, _0);
}

void crypto_lock_detached(uint8_t        mac[16],
                          uint8_t       *ciphertext,
                          const uint8_t  your_secret_key [32],
                          const uint8_t  their_public_key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *plaintext,
                          size_t         text_size)
{
    uint8_t shared_key[32];
    crypto_lock_key(shared_key, your_secret_key, their_public_key);
    crypto_ae_lock_detached(mac, ciphertext,
                            shared_key, nonce,
                            plaintext, text_size);
}

int crypto_unlock_detached(uint8_t       *plaintext,
                           const uint8_t  your_secret_key [32],
                           const uint8_t  their_public_key[32],
                           const uint8_t  nonce[24],
                           const uint8_t  mac[16],
                           const uint8_t *ciphertext,
                           size_t         text_size)
{
    uint8_t shared_key[32];
    crypto_lock_key(shared_key, your_secret_key, their_public_key);
    return crypto_ae_unlock_detached(plaintext,
                                     shared_key, nonce,
                                     mac, ciphertext, text_size);
}

void crypto_lock(uint8_t       *box,
                 const uint8_t  your_secret_key [32],
                 const uint8_t  their_public_key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *plaintext,
                 size_t         text_size)
{
    crypto_lock_detached(box, box + 16,
                         your_secret_key, their_public_key, nonce,
                         plaintext, text_size);
}

int crypto_unlock(uint8_t       *plaintext,
                  const uint8_t  your_secret_key [32],
                  const uint8_t  their_public_key[32],
                  const uint8_t  nonce[24],
                  const uint8_t *box,
                  size_t         text_size)
{
    return crypto_unlock_detached(plaintext,
                                  your_secret_key, their_public_key, nonce,
                                  box, box + 16, text_size);
}

static const uint8_t null_nonce[24] = {};

void crypto_anonymous_lock(uint8_t       *box,
                           const uint8_t  random_secret_key[32],
                           const uint8_t  their_public_key[32],
                           const uint8_t *plaintext,
                           size_t         text_size)
{
    crypto_x25519_base(box, random_secret_key); // put public key in box
    crypto_lock(box + 32,
                random_secret_key, their_public_key, null_nonce,
                plaintext, text_size);
}

int crypto_anonymous_unlock(uint8_t       *plaintext,
                            const uint8_t  your_secret_key[32],
                            const uint8_t *box,
                            size_t         text_size)
{
    return crypto_unlock(plaintext,
                         your_secret_key, box, null_nonce,
                         box + 32, text_size);
}
