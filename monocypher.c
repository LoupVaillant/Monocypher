#include "monocypher.h"

/////////////////
/// Utilities ///
/////////////////

// By default, ed25519 uses blake2b.
// sha512 is provided as an option for compatibility
// and testability against official test vectors.
// Compile with option -DED25519_SHA512 to use with sha512
// If you do so, you must provide the "sha512" header with
// suitable functions.
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

#define FOR(i, start, end) for (size_t i = start; i < end; i++)
#define sv static void
typedef  int8_t   i8;
typedef uint8_t   u8;
typedef uint32_t u32;
typedef  int32_t i32;
typedef  int64_t i64;
typedef uint64_t u64;

static u32 load32_le(const u8 s[4])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16)
        | ((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
    return
        ((u64)s[0]      ) ^
        ((u64)s[1] <<  8) ^
        ((u64)s[2] << 16) ^
        ((u64)s[3] << 24) ^
        ((u64)s[4] << 32) ^
        ((u64)s[5] << 40) ^
        ((u64)s[6] << 48) ^
        ((u64)s[7] << 56);
}

sv store32_le(u8 output[4], u32 input)
{
    output[0] =  input        & 0xff;
    output[1] = (input >>  8) & 0xff;
    output[2] = (input >> 16) & 0xff;
    output[3] = (input >> 24) & 0xff;
}

sv store64_le(u8 output[8], u64 input)
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

static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }
static u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

int crypto_memcmp(const u8 *p1, const u8 *p2, size_t n)
{
    unsigned diff = 0;
    FOR (i, 0, n) { diff |= (p1[i] ^ p2[i]); }
    return diff;
}

/////////////////
/// Chacha 20 ///
/////////////////
#define QUARTERROUND(a, b, c, d)          \
    a += b;  d ^= a;  d = rotl32(d, 16);  \
    c += d;  b ^= c;  b = rotl32(b, 12);  \
    a += b;  d ^= a;  d = rotl32(d,  8);  \
    c += d;  b ^= c;  b = rotl32(b,  7)

sv chacha20_rounds(u32 out[16], const u32 in[16])
{
    FOR (i, 0, 16) { out[i] = in[i]; }
    FOR (i, 0, 10) { // 20 rounds, 2 rounds per loop.
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

sv chacha20_init_key(crypto_chacha_ctx *ctx, const u8 key[32])
{
    // constant
    ctx->input[0] = load32_le((u8*)"expa");
    ctx->input[1] = load32_le((u8*)"nd 3");
    ctx->input[2] = load32_le((u8*)"2-by");
    ctx->input[3] = load32_le((u8*)"te k");
    // key
    FOR (i, 0, 8) {
        ctx->input[i+4] = load32_le(key + i*4);
    }
    // pool index (the random pool starts empty)
    ctx->pool_index = 64;
}

void crypto_chacha20_H(u8 out[32], const u8 key[32], const u8 in[16])
{
    crypto_chacha_ctx ctx;
    chacha20_init_key(&ctx, key);
    FOR (i, 0, 4) {
        ctx.input[i+12] = load32_le(in + i*4);
    }
    u32 buffer[16];
    chacha20_rounds(buffer, ctx.input);
    // prevents reversal of the rounds by revealing only half of the buffer.
    FOR (i, 0, 4) {
        store32_le(out      + i*4, buffer[i     ]); // constant
        store32_le(out + 16 + i*4, buffer[i + 12]); // counter and nonce
    }
}

void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                          const u8           key[32],
                          const u8           nonce[8])
{
    chacha20_init_key(ctx, key  );         // key
    ctx->input[12] = 0;                    // counter
    ctx->input[13] = 0;                    // counter
    ctx->input[14] = load32_le(nonce + 0); // nonce
    ctx->input[15] = load32_le(nonce + 4); // nonce
}

void crypto_chacha20_Xinit(crypto_chacha_ctx *ctx,
                           const u8           key[32],
                           const u8           nonce[24])
{
    u8 derived_key[32];
    crypto_chacha20_H(derived_key, key, nonce);
    crypto_chacha20_init(ctx, derived_key, nonce + 16);
}

void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                             const u8          *plain_text,
                             u8                *cipher_text,
                             size_t             message_size)
{
    FOR (i, 0, message_size) {
        // refill the pool if empty
        if (ctx->pool_index == 64) {
            // fill the pool
            u32 buffer[16];
            chacha20_rounds(buffer, ctx->input);
            FOR (i, 0, 16) {
                store32_le(ctx->random_pool + i*4, buffer[i] + ctx->input[i]);
            }
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

void crypto_chacha20_random(crypto_chacha_ctx *ctx,
                            u8                *cipher_text,
                            size_t             message_size)
{
    crypto_chacha20_encrypt(ctx, 0, cipher_text, message_size);
}


/////////////////
/// Poly 1305 ///
/////////////////
sv poly_load(u32 out[4], const u8 in[16])
{
    FOR (i, 0, 4) { out[i] = load32_le(in + i*4); }
}

sv poly_add(u32 out[5], const u32 a[5], const u32 b[5])
{
    u64 carry = 0;
    FOR (i, 0, 5) {
        carry  += (i64)(a[i]) + b[i];
        out[i]  = carry & 0xffffffff; // lower 32 bits right there.
        carry >>= 32;                 // retain the carry
    }
}

// h = (h + c) * r
sv poly_block(crypto_poly1305_ctx *ctx)
{
    // h + c, without carry propagation
    const u64 h0 = ctx->h[0] + (u64)ctx->c[0];
    const u64 h1 = ctx->h[1] + (u64)ctx->c[1];
    const u64 h2 = ctx->h[2] + (u64)ctx->c[2];
    const u64 h3 = ctx->h[3] + (u64)ctx->c[3];
    const u64 h4 = ctx->h[4] + (u64)ctx->c[4];

    // Local all the things!
    const u64 r0 = ctx->r[0];
    const u64 r1 = ctx->r[1];
    const u64 r2 = ctx->r[2];
    const u64 r3 = ctx->r[3];
    const u64 rr0 = (ctx->r[0] >> 2) * 5; // lose 2 bottom bits...
    const u64 rr1 = (ctx->r[1] >> 2) * 5; // 2 bottom bits already cleared
    const u64 rr2 = (ctx->r[2] >> 2) * 5; // 2 bottom bits already cleared
    const u64 rr3 = (ctx->r[3] >> 2) * 5; // 2 bottom bits already cleared

    // (h + c) * r, without carry propagation
    const u64 x0 = h0*r0 + h1*rr3 + h2*rr2 + h3*rr1 + h4*rr0;
    const u64 x1 = h0*r1 + h1*r0  + h2*rr3 + h3*rr2 + h4*rr1;
    const u64 x2 = h0*r2 + h1*r1  + h2*r0  + h3*rr3 + h4*rr2;
    const u64 x3 = h0*r3 + h1*r2  + h2*r1  + h3*r0  + h4*rr3;
    const u64 x4 = h4 * (r0 & 3); // ...recover those 2 bits

    // carry propagation, put ctx->h under 2^130
    const u64 msb = x4 + (x3 >> 32);
    u64       u   = (msb >> 2) * 5; // lose 2 bottom bits...
    u += (x0 & 0xffffffff)             ;  ctx->h[0] = u & 0xffffffff;  u >>= 32;
    u += (x1 & 0xffffffff) + (x0 >> 32);  ctx->h[1] = u & 0xffffffff;  u >>= 32;
    u += (x2 & 0xffffffff) + (x1 >> 32);  ctx->h[2] = u & 0xffffffff;  u >>= 32;
    u += (x3 & 0xffffffff) + (x2 >> 32);  ctx->h[3] = u & 0xffffffff;  u >>= 32;
    u += msb & 3 /* ...recover them */ ;  ctx->h[4] = u;
}

// (re-)initializes the input counter and input buffer
sv poly_clear_c(crypto_poly1305_ctx *ctx)
{
    FOR (i, 0, 4) { ctx->c[i] = 0; }
    ctx->c_index = 0;
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const u8 key[32])
{
    // initial h: zero
    FOR (i, 0, 5) { ctx->h [i] = 0; }
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
                            const u8 *m, size_t bytes)
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

void crypto_poly1305_finish(crypto_poly1305_ctx *ctx, u8 mac[16])
{
    // move the final 1 according to remaining input length
    ctx->c[4] = 0;
    ctx->c[ctx->c_index / 4] |= 1 << ((ctx->c_index % 4) * 8);
    // one last hash update...
    poly_block(ctx);
    // ... this time with full modular reduction
    // We only need to conditionally subtract 2^130-5,
    // using bit twidling to prevent timing attacks.
    static const u32 minus_p[5] = { 5, 0, 0, 0, 0xfffffffc };
    u32 h_minus_p[5];
    poly_add(h_minus_p, ctx->h, minus_p);
    u32 negative = ~(-(h_minus_p[4] >> 31)); // 0 or -1 (2's complement)
    for (int i = 0; i < 5; i++) {
        ctx->h[i] ^= negative & (ctx->h[i] ^ h_minus_p[i]);
    }
    // Add the secret pad to the final hash before output
    poly_add(ctx->h, ctx->h, ctx->pad);
    for (int i = 0; i < 4; i++)
        store32_le(mac + i*4, ctx->h[i]);
}

void crypto_poly1305_auth(u8 mac[16], const u8 *m,
                          size_t  m_size , const u8  key[32])
{
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, key);
    crypto_poly1305_update(&ctx, m, m_size);
    crypto_poly1305_finish(&ctx, mac);
}

////////////////
/// Blake2 b /// (taken from the reference
////////////////  implentation in RFC 7693)

// Initialization Vector.
static const u64 blake2b_iv[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

// increment a 128-bit "word".
sv incr(u64 x[2], u64 y)
{
    x[0] += y;                 // increment the low word
    if (x[0] < y) { x[1]++; }  // handle overflow
}

sv blake2b_compress(crypto_blake2b_ctx *ctx, int last_block)
{
    static const u8 sigma[12][16] = {
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
    u64 v[16];
    FOR (i, 0, 8) {
        v[i    ] = ctx->hash[i];
        v[i + 8] = blake2b_iv[i];
    }
    v[12] ^= ctx->input_size[0]; // low 64 bits of offset
    v[13] ^= ctx->input_size[1]; // high 64 bits
    if (last_block) { v[14] = ~v[14]; }

    // load the input buffer
    u64 m[16];
    FOR (i ,0, 16) { m[i] = load64_le(&ctx->buf[i * 8]); }

    // shuffle the work variables with the 12 rounds
    FOR (i, 0, 12) {
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
    FOR (i, 0, 8) { ctx->hash[i] ^= v[i] ^ v[i+8]; }
}

void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t outlen,
                                 const u8      *key, size_t keylen)
{
    // Initial hash == initialization vector...
    FOR (i, 0, 8) { ctx->hash[i] = blake2b_iv[i]; }
    ctx->hash[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;  // ...mostly

    ctx->input_size[0] = 0;       // input count low word
    ctx->input_size[1] = 0;       // input count high word
    ctx->c             = 0;       // pointer within buffer
    ctx->output_size   = outlen;  // size of the final hash

    // If there's a key, put it in the first block, then pad with zeroes
    if (keylen > 0) {
        FOR (i, 0     , keylen) { ctx->buf[i] = key[i]; }
        FOR (i, keylen, 128   ) { ctx->buf[i] = 0;      }
        ctx->c = 128; // mark the block as used
    }
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx)
{
    crypto_blake2b_general_init(ctx, 64, 0, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx, const u8 *in, size_t inlen)
{
    FOR (i, 0, inlen) {
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

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, u8 *out)
{
    // update input size, pad then compress the buffer
    incr(ctx->input_size, ctx->c);
    FOR (i, ctx->c, 128) { ctx->buf[i] = 0; }
    blake2b_compress(ctx, 1); // last time -> 1

    // copy the hash in the output (little endian of course)
    FOR (i, 0, ctx->output_size) {
        out[i] = (ctx->hash[i / 8] >> (8 * (i & 7))) & 0xFF;
    }
}

void crypto_blake2b_general(u8       *out, size_t outlen,
                            const u8 *key, size_t keylen,
                            const u8 *in,  size_t inlen)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, outlen, key, keylen);
    crypto_blake2b_update(&ctx, in, inlen);
    crypto_blake2b_final(&ctx, out);
}

void crypto_blake2b(u8 out[64], const u8 *in, size_t inlen)
{
    crypto_blake2b_general(out, 64, 0, 0, in, inlen);
}


////////////////
/// Argon2 i ///
////////////////
// references to R, Z, Q etc. come from the spec

typedef struct { u64 a[128]; } block; // 1024 octets

static u32 min(u32 a, u32 b) { return a <= b ? a : b; }

// updates a blake2 hash with a 32 bit word, little endian.
sv blake_update_32(crypto_blake2b_ctx *ctx, u32 input)
{
    u8 buf[4];
    store32_le(buf, input);
    crypto_blake2b_update(ctx, buf, 4);
}

sv load_block(block *b, const u8 bytes[1024])
{
    FOR (i, 0, 128) { b->a[i] = load64_le(bytes + i*8); }
}

sv store_block(u8 bytes[1024], const block *b)
{
    FOR (i, 0, 128) { store64_le(bytes + i*8, b->a[i]); }
}

sv copy_block(block *o, const block *in) { FOR (i, 0, 128) o->a[i]  = in->a[i]; }
sv  xor_block(block *o, const block *in) { FOR (i, 0, 128) o->a[i] ^= in->a[i]; }

// Hash with a virtually unlimited digest size.
// Doesn't extract more entropy than the base hash function.
// Mainly used for filling a whole kilobyte block with pseudo-random bytes.
sv extended_hash(u8       *digest, u32 digest_size,
                 const u8 *input , u32 input_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, min(digest_size, 64), 0, 0);
    blake_update_32            (&ctx, digest_size);
    crypto_blake2b_update      (&ctx, input, input_size);
    crypto_blake2b_final       (&ctx, digest);

    if (digest_size > 64) {
        // the conversion to u64 avoids integer overflow on
        // ludicrously big hash sizes.
        u32 r   = (((u64)digest_size + 31) / 32) - 2;
        u32 i   =  1;
        u32 in  =  0;
        u32 out = 32;
        while (i < r) {
            // Input and output overlap. This is intentional
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

// Core of the compression function G.  Computes Z from R in place.
sv g_rounds(block *work_block)
{
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
sv binary_g(block *result, const block *x, const block *y,
            void (*xcopy) (block*, const block*))
{
    block tmp;
    copy_block(&tmp, x);     // tmp    = X
    xor_block (&tmp, y);     // tmp    = X ^ Y = R
    xcopy(result, &tmp);     // result = R     (or R ^ old)
    g_rounds(&tmp);          // tmp    = Z
    xor_block(result, &tmp); // result = R ^ Z (or R ^ old ^ Z)
}

// unary version of the compression function.
// The missing argument is implied zero.
// Does the transformation in place.
sv unary_g(block *work_block)
{
    // work_block == R
    block tmp;
    copy_block(&tmp, work_block); // tmp        = R
    g_rounds(work_block);         // work_block = Z
    xor_block(work_block, &tmp);  // work_block = Z ^ R
}

typedef struct {
    block b;
    u32   pass_number;
    u32   slice_number;
    u32   nb_blocks;
    u32   nb_iterations;
    u32   ctr;
    u32   index;
} gidx_ctx;

sv gidx_refresh(gidx_ctx *ctx)
{
    // seed the begining of the block...
    ctx->b.a[0] = ctx->pass_number;
    ctx->b.a[1] = 0;  // lane number (we have only one)
    ctx->b.a[2] = ctx->slice_number;
    ctx->b.a[3] = ctx->nb_blocks;
    ctx->b.a[4] = ctx->nb_iterations;
    ctx->b.a[5] = 1;  // type: Argon2i
    ctx->b.a[6] = ctx->ctr;
    FOR (i, 7, 128) { ctx->b.a[i] = 0; } // then zero the rest out

    // Shuffle the block thus: ctx->b = G((G(ctx->b, zero)), zero)
    // Applies the G "square" function to get cheap pseudo-random numbers.
    unary_g(&(ctx->b));
    unary_g(&(ctx->b));
}

sv gidx_init(gidx_ctx *ctx,
             u32 pass_number, u32 slice_number,
             u32 nb_blocks,   u32 nb_iterations)
{
    ctx->pass_number   = pass_number;
    ctx->slice_number  = slice_number;
    ctx->nb_blocks     = nb_blocks;
    ctx->nb_iterations = nb_iterations;
    ctx->ctr           = 1;   // not zero, surprisingly
    ctx->index         = pass_number == 0 && slice_number == 0 ? 2 : 0;
    // Quirk from the reference implementation: for the first pass,
    // ctx->index is set at 2, because the first pseudo-random index
    // we need is used for the *third* block of the segment.
    // Setting it at zero every time wouldn't affect security.
    gidx_refresh(ctx);
}

static u32 gidx_next(gidx_ctx *ctx)
{
    // lazily creates the index block we need
    if (ctx->index == 128) {
        ctx->index = 0;
        ctx->ctr++;
        gidx_refresh(ctx);
    }
    // saves and increment the index
    u32 index = ctx->index;
    ctx->index++; // updates index for the next call

    // Computes the area size.
    // Pass 0 : all already finished segments plus already constructed
    //          blocks in this segment
    // Pass 1+: 3 last segments plus already constructed
    //          blocks in this segment.  THE SPEC SUGGESTS OTHERWISE.
    //          I CONFORM TO THE REFERENCE IMPLEMENTATION.
    int first_pass = ctx->pass_number == 0;
    u32 slice_size = ctx->nb_blocks / 4;
    u32 area_size  = ((first_pass ? ctx->slice_number : 3)
                      * slice_size + index - 1);

    // Computes the starting position of the reference area.
    // CONTRARY TO WHAT THE SPEC SUGGESTS, IT STARTS AT THE
    // NEXT SEGMENT, NOT THE NEXT BLOCK.
    u32 next_slice = (ctx->slice_number == 3
                      ? 0
                      : (ctx->slice_number + 1) * slice_size);
    u32 start_pos  = first_pass ? 0 : next_slice;

    // Generates the actual index from J1 (no need for J2, there's only one lane)
    u64 j1         = ctx->b.a[index] & 0xffffffff; // pseudo-random number
    u64 x          = (j1 * j1)       >> 32;
    u64 y          = (area_size * x) >> 32;
    u64 z          = area_size - 1 - y;
    return (start_pos + z) % ctx->nb_blocks;
}

// Main algorithm
void crypto_argon2i(u8       *tag,      u32 tag_size,
                    const u8 *password, u32 password_size,
                    const u8 *salt,     u32 salt_size,
                    const u8 *key,      u32 key_size,
                    const u8 *ad,       u32 ad_size,
                    void *work_area,
                    u32 nb_blocks,
                    u32 nb_iterations)
{
    // work area seen as blocks (must be suitably aligned)
    block *blocks = (block*)work_area;
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

        u8 initial_hash[72]; // 64 bytes plus 2 words for future hashes
        crypto_blake2b_final(&ctx, initial_hash);

        // fill first 2 blocks
        block   tmp_block;
        u8 hash_area[1024];
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
    const u32 segment_size = nb_blocks / 4;

    // fill (then re-fill) the rest of the blocks
    FOR (pass_number, 0, nb_iterations) {
        int first_pass  = pass_number == 0;
        // Simple copy on pass 0, XOR instead of overwrite on subsequent passes
        void (*xcopy) (block*, const block*) = first_pass ?copy_block :xor_block;

        FOR (segment, 0, 4) {
            gidx_ctx ctx;
            gidx_init(&ctx, pass_number, segment, nb_blocks, nb_iterations);

            // On the first segment of the first pass,
            // blocks 0 and 1 are already filled.
            // We use the offset to skip them.
            u32 offset = first_pass && segment == 0 ? 2 : 0;
            // current, reference, and previous are block indices
            FOR (current,
                 segment * segment_size + offset,
                 (segment + 1) * segment_size) {
                u32 previous  = current == 0 ? nb_blocks - 1 : current - 1;
                u32 reference = gidx_next(&ctx);
                binary_g(blocks + current,
                         blocks + previous,
                         blocks + reference,
                         xcopy);
            }
        }
    }
    // hash the very last block with H' into the output tag
    u8 final_block[1024];
    store_block(final_block, blocks + (nb_blocks - 1));
    extended_hash(tag, tag_size, final_block, 1024);
}

////////////////////////////////////
/// Arithmetic modulo 2^255 - 19 /// Taken from Supercop's ref10 implementation.
//////////////////////////////////// A bit bigger than TweetNaCl, much faster.

// field element
typedef i32 fe[10];

sv fe_0   (fe h) {                         FOR (i, 0, 10) h[i] = 0;           }
sv fe_1   (fe h) {              h[0] = 1;  FOR (i, 1, 10) h[i] = 0;           }
sv fe_neg (fe h, const fe f)             { FOR (i, 0, 10) h[i] = -f[i];       }
sv fe_add (fe h, const fe f, const fe g) { FOR (i, 0, 10) h[i] = f[i] + g[i]; }
sv fe_sub (fe h, const fe f, const fe g) { FOR (i, 0, 10) h[i] = f[i] - g[i]; }
sv fe_copy(fe h, const fe f            ) { FOR (i, 0, 10) h[i] = f[i];        }

sv fe_cswap(fe f, fe g, u32 b)
{
    FOR (i, 0, 10) {
        i32 x = (f[i] ^ g[i]) & -b;
        f[i] = f[i] ^ x;
        g[i] = g[i] ^ x;
    }
}

static u32 load24_le(const u8 s[3])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16);
}

sv fe_carry(fe h, i64 t[10])
{
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;
    c9 = (t[9] + (i64) (1<<24)) >> 25; t[0] += c9 * 19; t[9] -= c9 << 25;
    c1 = (t[1] + (i64) (1<<24)) >> 25; t[2] += c1;      t[1] -= c1 << 25;
    c3 = (t[3] + (i64) (1<<24)) >> 25; t[4] += c3;      t[3] -= c3 << 25;
    c5 = (t[5] + (i64) (1<<24)) >> 25; t[6] += c5;      t[5] -= c5 << 25;
    c7 = (t[7] + (i64) (1<<24)) >> 25; t[8] += c7;      t[7] -= c7 << 25;
    c0 = (t[0] + (i64) (1<<25)) >> 26; t[1] += c0;      t[0] -= c0 << 26;
    c2 = (t[2] + (i64) (1<<25)) >> 26; t[3] += c2;      t[2] -= c2 << 26;
    c4 = (t[4] + (i64) (1<<25)) >> 26; t[5] += c4;      t[4] -= c4 << 26;
    c6 = (t[6] + (i64) (1<<25)) >> 26; t[7] += c6;      t[6] -= c6 << 26;
    c8 = (t[8] + (i64) (1<<25)) >> 26; t[9] += c8;      t[8] -= c8 << 26;
    FOR (i, 0, 10) { h[i] = t[i]; }
}

sv fe_frombytes(fe h, const u8 s[32])
{
    i64 t[10]; // intermediate result (may overflow 32 bits)
    t[0] =  load32_le(s);
    t[1] =  load24_le(s +  4) << 6;
    t[2] =  load24_le(s +  7) << 5;
    t[3] =  load24_le(s + 10) << 3;
    t[4] =  load24_le(s + 13) << 2;
    t[5] =  load32_le(s + 16);
    t[6] =  load24_le(s + 20) << 7;
    t[7] =  load24_le(s + 23) << 5;
    t[8] =  load24_le(s + 26) << 4;
    t[9] = (load24_le(s + 29) & 8388607) << 2;
    fe_carry(h, t);
}

sv fe_mul121666(fe h, const fe f)
{
    i64 t[10];
    FOR(i, 0, 10) { t[i] = f[i] * (i64) 121666; }
    fe_carry(h, t);
}

sv fe_mul(fe h, const fe f, const fe g)
{
    // Everything is unrolled and put in temporary variables.
    // We could roll the loop, but that would make it twice as slow.
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 g0 = g[0]; i32 g1 = g[1]; i32 g2 = g[2]; i32 g3 = g[3]; i32 g4 = g[4];
    i32 g5 = g[5]; i32 g6 = g[6]; i32 g7 = g[7]; i32 g8 = g[8]; i32 g9 = g[9];
    i32 F1 = f1*2; i32 F3 = f3*2; i32 F5 = f5*2; i32 F7 = f7*2; i32 F9 = f9*2;
    i32 G1 = g1*19;  i32 G2 = g2*19;  i32 G3 = g3*19;
    i32 G4 = g4*19;  i32 G5 = g5*19;  i32 G6 = g6*19;
    i32 G7 = g7*19;  i32 G8 = g8*19;  i32 G9 = g9*19;

    i64 h0 = f0*(i64)g0 + F1*(i64)G9 + f2*(i64)G8 + F3*(i64)G7 + f4*(i64)G6
        +    F5*(i64)G5 + f6*(i64)G4 + F7*(i64)G3 + f8*(i64)G2 + F9*(i64)G1;
    i64 h1 = f0*(i64)g1 + f1*(i64)g0 + f2*(i64)G9 + f3*(i64)G8 + f4*(i64)G7
        +    f5*(i64)G6 + f6*(i64)G5 + f7*(i64)G4 + f8*(i64)G3 + f9*(i64)G2;
    i64 h2 = f0*(i64)g2 + F1*(i64)g1 + f2*(i64)g0 + F3*(i64)G9 + f4*(i64)G8
        +    F5*(i64)G7 + f6*(i64)G6 + F7*(i64)G5 + f8*(i64)G4 + F9*(i64)G3;
    i64 h3 = f0*(i64)g3 + f1*(i64)g2 + f2*(i64)g1 + f3*(i64)g0 + f4*(i64)G9
        +    f5*(i64)G8 + f6*(i64)G7 + f7*(i64)G6 + f8*(i64)G5 + f9*(i64)G4;
    i64 h4 = f0*(i64)g4 + F1*(i64)g3 + f2*(i64)g2 + F3*(i64)g1 + f4*(i64)g0
        +    F5*(i64)G9 + f6*(i64)G8 + F7*(i64)G7 + f8*(i64)G6 + F9*(i64)G5;
    i64 h5 = f0*(i64)g5 + f1*(i64)g4 + f2*(i64)g3 + f3*(i64)g2 + f4*(i64)g1
        +    f5*(i64)g0 + f6*(i64)G9 + f7*(i64)G8 + f8*(i64)G7 + f9*(i64)G6;
    i64 h6 = f0*(i64)g6 + F1*(i64)g5 + f2*(i64)g4 + F3*(i64)g3 + f4*(i64)g2
        +    F5*(i64)g1 + f6*(i64)g0 + F7*(i64)G9 + f8*(i64)G8 + F9*(i64)G7;
    i64 h7 = f0*(i64)g7 + f1*(i64)g6 + f2*(i64)g5 + f3*(i64)g4 + f4*(i64)g3
        +    f5*(i64)g2 + f6*(i64)g1 + f7*(i64)g0 + f8*(i64)G9 + f9*(i64)G8;
    i64 h8 = f0*(i64)g8 + F1*(i64)g7 + f2*(i64)g6 + F3*(i64)g5 + f4*(i64)g4
        +    F5*(i64)g3 + f6*(i64)g2 + F7*(i64)g1 + f8*(i64)g0 + F9*(i64)G9;
    i64 h9 = f0*(i64)g9 + f1*(i64)g8 + f2*(i64)g7 + f3*(i64)g6 + f4*(i64)g5
        +    f5*(i64)g4 + f6*(i64)g3 + f7*(i64)g2 + f8*(i64)g1 + f9*(i64)g0;

#define CARRY_MULT                                                  \
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;                     \
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 << 26; \
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 << 26; \
    c1 = (h1 + (i64) (1<<24)) >> 25; h2 += c1;      h1 -= c1 << 25; \
    c5 = (h5 + (i64) (1<<24)) >> 25; h6 += c5;      h5 -= c5 << 25; \
    c2 = (h2 + (i64) (1<<25)) >> 26; h3 += c2;      h2 -= c2 << 26; \
    c6 = (h6 + (i64) (1<<25)) >> 26; h7 += c6;      h6 -= c6 << 26; \
    c3 = (h3 + (i64) (1<<24)) >> 25; h4 += c3;      h3 -= c3 << 25; \
    c7 = (h7 + (i64) (1<<24)) >> 25; h8 += c7;      h7 -= c7 << 25; \
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 << 26; \
    c8 = (h8 + (i64) (1<<25)) >> 26; h9 += c8;      h8 -= c8 << 26; \
    c9 = (h9 + (i64) (1<<24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25; \
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 << 26; \
                                                                    \
    h[0] = h0;  h[1] = h1;  h[2] = h2;  h[3] = h3;  h[4] = h4;      \
    h[5] = h5;  h[6] = h6;  h[7] = h7;  h[8] = h8;  h[9] = h9
    CARRY_MULT;
}

sv fe_sq(fe h, const fe f)
{
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 f0_2  = f0*2;   i32 f1_2  = f1*2;   i32 f2_2  = f2*2;   i32 f3_2 = f3*2;
    i32 f4_2  = f4*2;   i32 f5_2  = f5*2;   i32 f6_2  = f6*2;   i32 f7_2 = f7*2;
    i32 f5_38 = f5*38;  i32 f6_19 = f6*19;  i32 f7_38 = f7*38;
    i32 f8_19 = f8*19;  i32 f9_38 = f9*38;

    i64 h0 = f0  *(i64)f0    + f1_2*(i64)f9_38 + f2_2*(i64)f8_19
        +    f3_2*(i64)f7_38 + f4_2*(i64)f6_19 + f5  *(i64)f5_38;
    i64 h1 = f0_2*(i64)f1    + f2  *(i64)f9_38 + f3_2*(i64)f8_19
        +    f4  *(i64)f7_38 + f5_2*(i64)f6_19;
    i64 h2 = f0_2*(i64)f2    + f1_2*(i64)f1    + f3_2*(i64)f9_38
        +    f4_2*(i64)f8_19 + f5_2*(i64)f7_38 + f6  *(i64)f6_19;
    i64 h3 = f0_2*(i64)f3    + f1_2*(i64)f2    + f4  *(i64)f9_38
        +    f5_2*(i64)f8_19 + f6  *(i64)f7_38;
    i64 h4 = f0_2*(i64)f4    + f1_2*(i64)f3_2  + f2  *(i64)f2
        +    f5_2*(i64)f9_38 + f6_2*(i64)f8_19 + f7  *(i64)f7_38;
    i64 h5 = f0_2*(i64)f5    + f1_2*(i64)f4    + f2_2*(i64)f3
        +    f6  *(i64)f9_38 + f7_2*(i64)f8_19;
    i64 h6 = f0_2*(i64)f6    + f1_2*(i64)f5_2  + f2_2*(i64)f4
        +    f3_2*(i64)f3    + f7_2*(i64)f9_38 + f8  *(i64)f8_19;
    i64 h7 = f0_2*(i64)f7    + f1_2*(i64)f6    + f2_2*(i64)f5
        +    f3_2*(i64)f4    + f8  *(i64)f9_38;
    i64 h8 = f0_2*(i64)f8    + f1_2*(i64)f7_2  + f2_2*(i64)f6
        +    f3_2*(i64)f5_2  + f4  *(i64)f4    + f9  *(i64)f9_38;
    i64 h9 = f0_2*(i64)f9    + f1_2*(i64)f8    + f2_2*(i64)f7
        +    f3_2*(i64)f6    + f4  *(i64)f5_2;
    CARRY_MULT;
}

sv fe_invert(fe out, const fe z)
{
    /*
    fe c; fe_copy(c, z);
    FOR (i, 0, 254) {
        fe_sq(c, c);
        if(i !=251 && i!= 249) fe_mul(c, c, z);
    }
    fe_copy(out, c);
    */
    fe t0, t1, t2, t3;
    fe_sq(t0, z );
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1,  z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);                                fe_mul(t1 , t1, t2);
    fe_sq(t2, t1); FOR (i, 1,   5) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); FOR (i, 1,  10) fe_sq(t2, t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); FOR (i, 1,  20) fe_sq(t3, t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); FOR (i, 1,  10) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); FOR (i, 1,  50) fe_sq(t2, t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); FOR (i, 1, 100) fe_sq(t3, t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); FOR (i, 1,  50) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t1, t1); FOR (i, 1,   5) fe_sq(t1, t1); fe_mul(out, t1, t0);

}

void fe_pow22523(fe out, const fe z)
{
    /*
    fe c; fe_copy(c, z);
    FOR(i, 0, 251) {
        fe_sq (c, c);
        if (i != 249) fe_mul(c, c, z);
    }
    fe_copy(out, c);
    */
    fe t0, t1, t2;
    fe_sq(t0, z);
    fe_sq(t1,t0);                   fe_sq(t1, t1);  fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);                                  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,   5) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  FOR (i, 1,  20) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  FOR (i, 1, 100) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t0, t0);  FOR (i, 1,   2) fe_sq(t0, t0);  fe_mul(out, t0, z);

}

sv fe_tobytes(u8 s[32], const fe h)
{
    i32 t[11];
    FOR (i, 0, 10) { t[i] = h[i]; }

    i32 q = (19 * t[9] + (((i32) 1) << 24)) >> 25;
    FOR (i, 0, 5) {
        q += t[2*i  ]; q >>= 26;
        q += t[2*i+1]; q >>= 25;
    }
    t[0] += 19 * q;
    FOR (i, 0, 5) {
        i32 carry;
        carry = t[2*i  ] >> 26; t[2*i+1] += carry; t[2*i  ] -= carry << 26;
        carry = t[2*i+1] >> 25; t[2*i+2] += carry; t[2*i+1] -= carry << 25;
    }
    store32_le(s +  0, ((u32)t[0] >>  0) | ((u32)t[1] << 26));
    store32_le(s +  4, ((u32)t[1] >>  6) | ((u32)t[2] << 19));
    store32_le(s +  8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
    store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] <<  6));
    store32_le(s + 16, ((u32)t[5] <<  0) | ((u32)t[6] << 25));
    store32_le(s + 20, ((u32)t[6] >>  7) | ((u32)t[7] << 19));
    store32_le(s + 24, ((u32)t[7] >> 13) | ((u32)t[8] << 12));
    store32_le(s + 28, ((u32)t[8] >> 20) | ((u32)t[9] <<  6));
}

//  Parity check.  Returns 0 if even, 1 if odd
static int fe_isnegative(const fe f)
{
    u8 s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static int fe_isnonzero(const fe f)
{
    static const u8 zero[32];
    u8 s[32];
    fe_tobytes(s, f);
    return crypto_memcmp(s, zero, 32);
}

///////////////
/// X-25519 /// Taken from Supercop's ref10 implementation.
/////////////// Bigger than TweetNaCl, but over 8 times faster
sv trim_scalar(u8 s[32])
{
    s[ 0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

void crypto_x25519(u8       shared_secret   [32],
                   const u8 your_secret_key [32],
                   const u8 their_public_key[32])
{
    // computes the scalar product
    fe x1, x2, z2, x3, z3;
    fe_frombytes(x1, their_public_key);

    // restrict the possible scalar values
    u8 e[32]; FOR (i, 0, 32) { e[i] = your_secret_key[i]; }
    trim_scalar(e);

    // Montgomery ladder
    // We work in projective coordinates to avoid divisons: x = X / Z
    // We don't care about the y coordinate.
    fe_1(x2);        fe_0(z2); // "zero" point
    fe_copy(x3, x1); fe_1(z3); // "one"  point
    u32 swap = 0;
    for (int pos = 254; pos >= 0; --pos) {
        // constant time conditional swap before ladder step
        u32 b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b; // xor trick avoids swapping at the end of the loop
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;  // anticipates one last swap after the loop

        // Montgomery ladder step: replaces (P2, P3) by (P2*2, P2+P3)
        // with differential addition
        fe t0, t1;
        fe_sub(t0, x3, z3);  fe_sub(t1, x2, z2);    fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);  fe_mul(z3, t0, x2);    fe_mul(z2, z2, t1);
        fe_sq (t0, t1    );  fe_sq (t1, x2    );    fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);  fe_mul(x2, t1, t0);    fe_sub(t1, t1, t0);
        fe_sq (z2, z2    );  fe_mul121666(z3, t1);  fe_sq (x3, x3    );
        fe_add(t0, t0, z3);  fe_mul(z3, x1, z2);    fe_mul(z2, t1, t0);
    }
    // last swap is necessary to compensate for the xor trick
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    // normalises the coordinates: x == X / Z
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(shared_secret, x2);
}

void crypto_x25519_public_key(u8       public_key[32],
                              const u8 secret_key[32])
{
    static const u8 base_point[32] = {9};
    crypto_x25519(public_key, secret_key, base_point);
}

///////////////
/// Ed25519 ///
///////////////

// Point in a twisted Edwards curve,
// in extended projective coordinates
// x = X/Z, y = Y/Z, T = XY/Z
typedef struct { fe X; fe Y; fe Z; fe T; } ge;

sv ge_from_xy(ge *p, const fe x, const fe y)
{
    FOR (i, 0, 10) {
        p->X[i] = x[i];
        p->Y[i] = y[i];
    }
    fe_1  (p->Z);
    fe_mul(p->T, x, y);
}

sv ge_cswap(ge *p, ge *q, u32 b)
{
    fe_cswap(p->X, q->X, b);
    fe_cswap(p->Y, q->Y, b);
    fe_cswap(p->Z, q->Z, b);
    fe_cswap(p->T, q->T, b);
}

sv ge_tobytes(u8 s[32], const ge *h)
{
    fe recip, x, y;
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

// Variable time! s must not be secret!
static int ge_frombytes_neg(ge *h, const u8 s[32])
{
    static const fe d = {
        -10913610,13857413,-15372611,6949391,114729,
        -8787816,-6275908,-3247719,-18696448,-12055116
    } ;
    static const fe sqrtm1 = {
        -32595792,-7943725,9377950,3500415,12389472,
        -272473,-25146209,-2005654,326686,11406482
    } ;
    fe u, v, v3, vxx, check;
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);          // y^2
    fe_mul(v, u, d);
    fe_sub(u, u, h->Z);       // u = y^2-1
    fe_add(v, v, h->Z);       // v = dy^2+1

    fe_sq(v3, v);
    fe_mul(v3, v3, v);        // v3 = v^3
    fe_sq(h->X, v3);
    fe_mul(h->X, h->X, v);
    fe_mul(h->X, h->X, u);    // x = uv^7

    fe_pow22523(h->X, h->X); // x = (uv^7)^((q-5)/8)
    fe_mul(h->X, h->X, v3);
    fe_mul(h->X, h->X, u);    // x = uv^3(uv^7)^((q-5)/8)

    fe_sq(vxx, h->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);    // vx^2-u
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u);  // vx^2+u
        if (fe_isnonzero(check)) return -1;
        fe_mul(h->X, h->X, sqrtm1);
    }

    if (fe_isnegative(h->X) == (s[31] >> 7))
        fe_neg(h->X, h->X);

    fe_mul(h->T, h->X, h->Y);
    return 0;
}

sv ge_add(ge *s, const ge *p, const ge *q)
{
    static const fe D2 = { // - 2 * 121665 / 121666
        0x2b2f159, 0x1a6e509, 0x22add7a, 0x0d4141d, 0x0038052,
        0x0f3d130, 0x3407977, 0x19ce331, 0x1c56dff, 0x0901b67
    };
    fe a, b, c, d, e, f, g, h;
    //  A = (Y1-X1) * (Y2-X2)
    //  B = (Y1+X1) * (Y2+X2)
    fe_sub(a, p->Y, p->X);  fe_sub(h, q->Y, q->X);  fe_mul(a, a, h);
    fe_add(b, p->X, p->Y);  fe_add(h, q->X, q->Y);  fe_mul(b, b, h);
    fe_mul(c, p->T, q->T);  fe_mul(c, c, D2  );  //  C = T1 * k * T2
    fe_add(d, p->Z, p->Z);  fe_mul(d, d, q->Z);  //  D = Z1 * 2 * Z2
    fe_sub(e, b, a);     //  E  = B - A
    fe_sub(f, d, c);     //  F  = D - C
    fe_add(g, d, c);     //  G  = D + C
    fe_add(h, b, a);     //  H  = B + A
    fe_mul(s->X, e, f);  //  X3 = E * F
    fe_mul(s->Y, g, h);  //  Y3 = G * H
    fe_mul(s->Z, f, g);  //  T3 = E * H !error in the explicit formula database!
    fe_mul(s->T, e, h);  //  Z3 = F * G
}

sv ge_scalarmult(ge *p, const ge *q, const u8 scalar[32])
{
    ge t;
    fe_0(p->X);  fe_copy(t.X, q->X);
    fe_1(p->Y);  fe_copy(t.Y, q->Y);
    fe_1(p->Z);  fe_copy(t.Z, q->Z);
    fe_0(p->T);  fe_copy(t.T, q->T);

    for (int i = 255; i >= 0; i--) {
        u8 b = (scalar[i/8] >> (i & 7)) & 1;
        ge_cswap(p, &t, b);
        ge_add(&t, &t, p);
        ge_add(p , p , p);
        ge_cswap(p, &t, b);
    }
}

sv ge_scalarmult_base(ge *p, const u8 scalar[32])
{
    static const fe X = {
        0x325d51a, 0x18b5823, 0x0f6592a, 0x104a92d, 0x1a4b31d,
        0x1d6dc5c, 0x27118fe, 0x07fd814, 0x13cd6e5, 0x085a4db};
    static const fe Y = {
        0x2666658, 0x1999999, 0x0cccccc, 0x1333333, 0x1999999,
        0x0666666, 0x3333333, 0x0cccccc, 0x2666666, 0x1999999};
    ge base_point;
    ge_from_xy(&base_point, X, Y);
    ge_scalarmult(p, &base_point, scalar);
}

sv modL(u8 *r, i64 x[64])
{
    static const  u64 L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
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

// hashes R || A || M, reduces it modulo L
sv hash_ram(u8 k[64], const u8 R[32], const u8 A[32], const u8 *M, size_t M_size)
{
    HASH_CTX ctx;
    HASH_INIT  (&ctx);
    HASH_UPDATE(&ctx, R , 32    );
    HASH_UPDATE(&ctx, A , 32    );
    HASH_UPDATE(&ctx, M , M_size);
    HASH_FINAL (&ctx, k);
    reduce(k);
}

void crypto_ed25519_public_key(u8       public_key[32],
                               const u8 secret_key[32])
{
    u8 a[64];
    HASH(a, secret_key, 32);
    trim_scalar(a);
    ge A;
    ge_scalarmult_base(&A, a);
    ge_tobytes(public_key, &A);
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
    trim_scalar(a);

    ge A;
    u8 public_key[32];
    ge_scalarmult_base(&A, a);
    ge_tobytes(public_key, &A);

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

    ge R;
    reduce(r);
    ge_scalarmult_base(&R, r);
    ge_tobytes(signature, &R); // first half of the signature = "random" nonce

    u8 h_ram[64];
    hash_ram(h_ram, signature, public_key, message, message_size);

    i64 s[64]; // s = r + h_ram a
    FOR(i,  0, 32) s[i] = (u64) r[i];
    FOR(i, 32, 64) s[i] = 0;
    FOR(i, 0, 32) {
        FOR(j, 0, 32) {
            s[i+j] += h_ram[i] * (u64) a[j];
        }
    }
    modL(signature + 32, s);  // second half of the signature = s
}

int crypto_ed25519_check(const uint8_t  signature[64],
                         const uint8_t  public_key[32],
                         const uint8_t *message,
                         size_t         message_size)
{
    ge A, p, sB, diff;
    u8 h_ram[64], R_check[32];
    if (ge_frombytes_neg(&A, public_key)) return -1;  // -A
    hash_ram(h_ram, signature, public_key, message, message_size);
    ge_scalarmult(&p, &A, h_ram);                     // p    = -A*h_ram
    ge_scalarmult_base(&sB, signature + 32);
    ge_add(&diff, &p, &sB);                           // diff = s - A*h_ram
    ge_tobytes(R_check, &diff);
    return crypto_memcmp(signature, R_check, 32); // R == s - A*h_ram ? OK : fail
}

////////////////////////////////
/// Authenticated encryption ///
////////////////////////////////

void crypto_ae_lock_detached(u8        mac[16],
                             u8       *ciphertext,
                             const u8  key[32],
                             const u8  nonce[24],
                             const u8 *plaintext,
                             size_t         text_size)
{
    crypto_chacha_ctx e_ctx;
    u8           auth_key[32];
    crypto_chacha20_Xinit (&e_ctx, key, nonce);
    crypto_chacha20_random(&e_ctx, auth_key, 32);

    crypto_chacha20_encrypt(&e_ctx, plaintext, ciphertext, text_size);
    crypto_poly1305_auth(mac, ciphertext, text_size, auth_key);
}

int crypto_ae_unlock_detached(u8       *plaintext,
                              const u8  key[32],
                              const u8  nonce[24],
                              const u8  mac[16],
                              const u8 *ciphertext,
                              size_t         text_size)
{
    crypto_chacha_ctx e_ctx;
    u8           auth_key[32];
    crypto_chacha20_Xinit (&e_ctx, key, nonce);
    crypto_chacha20_random(&e_ctx, auth_key, 32);

    u8 real_mac[16];
    crypto_poly1305_auth(real_mac, ciphertext, text_size, auth_key);

    if (crypto_memcmp(real_mac, mac, 16))
        return -1;

    crypto_chacha20_encrypt(&e_ctx, ciphertext, plaintext, text_size);
    return 0;
}

void crypto_ae_lock(u8       *box,
                    const u8  key[32],
                    const u8  nonce[24],
                    const u8 *plaintext,
                    size_t         text_size)
{
    crypto_ae_lock_detached(box, box + 16, key, nonce, plaintext, text_size);
}

int crypto_ae_unlock(u8       *plaintext,
                     const u8  key[32],
                     const u8  nonce[24],
                     const u8 *box,
                     size_t         text_size)
{
    return crypto_ae_unlock_detached(plaintext, key, nonce,
                                     box, box + 16, text_size);
}

/////////////////////////////////////////////
/// Public key (authenticated) encryption ///
/////////////////////////////////////////////
void crypto_lock_key(u8       shared_key[32],
                     const u8 your_secret_key [32],
                     const u8 their_public_key[32])
{
    static const u8 _0[16] = {0};
    u8 shared_secret[32];
    crypto_x25519(shared_secret, your_secret_key, their_public_key);
    crypto_chacha20_H(shared_key, shared_secret, _0);
}

void crypto_lock_detached(u8        mac[16],
                          u8       *ciphertext,
                          const u8  your_secret_key [32],
                          const u8  their_public_key[32],
                          const u8  nonce[24],
                          const u8 *plaintext,
                          size_t    text_size)
{
    u8 shared_key[32];
    crypto_lock_key(shared_key, your_secret_key, their_public_key);
    crypto_ae_lock_detached(mac, ciphertext,
                            shared_key, nonce,
                            plaintext, text_size);
}

int crypto_unlock_detached(u8       *plaintext,
                           const u8  your_secret_key [32],
                           const u8  their_public_key[32],
                           const u8  nonce[24],
                           const u8  mac[16],
                           const u8 *ciphertext,
                           size_t    text_size)
{
    u8 shared_key[32];
    crypto_lock_key(shared_key, your_secret_key, their_public_key);
    return crypto_ae_unlock_detached(plaintext,
                                     shared_key, nonce,
                                     mac, ciphertext, text_size);
}

void crypto_lock(u8       *box,
                 const u8  your_secret_key [32],
                 const u8  their_public_key[32],
                 const u8  nonce[24],
                 const u8 *plaintext,
                 size_t    text_size)
{
    crypto_lock_detached(box, box + 16,
                         your_secret_key, their_public_key, nonce,
                         plaintext, text_size);
}

int crypto_unlock(u8       *plaintext,
                  const u8  your_secret_key [32],
                  const u8  their_public_key[32],
                  const u8  nonce[24],
                  const u8 *box,
                  size_t    text_size)
{
    return crypto_unlock_detached(plaintext,
                                  your_secret_key, their_public_key, nonce,
                                  box, box + 16, text_size);
}

static const u8 null_nonce[24] = {0};

void crypto_anonymous_lock(u8       *box,
                           const u8  random_secret_key[32],
                           const u8  their_public_key[32],
                           const u8 *plaintext,
                           size_t    text_size)
{
    crypto_x25519_public_key(box, random_secret_key); // put public key in box
    crypto_lock(box + 32,
                random_secret_key, their_public_key, null_nonce,
                plaintext, text_size);
}

int crypto_anonymous_unlock(u8       *plaintext,
                            const u8  your_secret_key[32],
                            const u8 *box,
                            size_t    text_size)
{
    return crypto_unlock(plaintext,
                         your_secret_key, box, null_nonce,
                         box + 32, text_size);
}
