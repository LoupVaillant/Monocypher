#include "monocypher.h"

/////////////////
/// Utilities ///
/////////////////

// By default, EdDSA signatures use blake2b.  SHA-512 is provided as
// an option for full ed25519 compatibility (a must for test vectors).
// Compile with option -DED25519_SHA512 to use with sha512.  If you do
// so, you must provide the "sha512" header with suitable functions.
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

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

static u32 load24_le(const u8 s[3])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16);
}

static u32 load32_le(const u8 s[4])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16)
        | ((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
    return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static void store32_le(u8 out[4], u32 in)
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}

static void store64_le(u8 out[8], u64 in)
{
    store32_le(out    , in      );
    store32_le(out + 4, in >> 32);
}

static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }
static u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

static int neq0(u64 diff)
{   // constant time comparison to zero
    // return diff != 0 ? -1 : 0
    u64 half = (diff >> 32) | ((u32)diff);
    return (1 & ((half - 1) >> 32)) - 1;
}

static u64 x16(const u8 a[16], const u8 b[16])
{
    return (load64_le(a + 0) ^ load64_le(b + 0))
        |  (load64_le(a + 8) ^ load64_le(b + 8));
}
static u64 x32(const u8 a[16],const u8 b[16]){return x16(a,b) ^ x16(a+16, b+16);}
static u64 x64(const u8 a[64],const u8 b[64]){return x32(a,b) ^ x32(a+32, b+32);}
int crypto_verify16(const u8 a[16], const u8 b[16]){ return neq0(x16(a, b)); }
int crypto_verify32(const u8 a[32], const u8 b[32]){ return neq0(x32(a, b)); }
int crypto_verify64(const u8 a[64], const u8 b[64]){ return neq0(x64(a, b)); }

static int zerocmp32(const u8 p[32])
{
    u8 zero[32] = {0};
    return crypto_verify32(p, zero);
}

void crypto_wipe(void *secret, size_t size)
{
    volatile u8 *v_secret = (u8*)secret;
    FOR (i, 0, size) {
        v_secret[i] = 0;
    }
}

/////////////////
/// Chacha 20 ///
/////////////////
#define QUARTERROUND(a, b, c, d)          \
    a += b;  d ^= a;  d = rotl32(d, 16);  \
    c += d;  b ^= c;  b = rotl32(b, 12);  \
    a += b;  d ^= a;  d = rotl32(d,  8);  \
    c += d;  b ^= c;  b = rotl32(b,  7)

static void chacha20_rounds(u32 out[16], const u32 in[16])
{
    // The temporary variables make Chacha20 10% faster.
    u32 t0  = in[ 0];  u32 t1  = in[ 1];  u32 t2  = in[ 2];  u32 t3  = in[ 3];
    u32 t4  = in[ 4];  u32 t5  = in[ 5];  u32 t6  = in[ 6];  u32 t7  = in[ 7];
    u32 t8  = in[ 8];  u32 t9  = in[ 9];  u32 t10 = in[10];  u32 t11 = in[11];
    u32 t12 = in[12];  u32 t13 = in[13];  u32 t14 = in[14];  u32 t15 = in[15];

    FOR (i, 0, 10) { // 20 rounds, 2 rounds per loop.
        QUARTERROUND(t0, t4, t8 , t12); // column 0
        QUARTERROUND(t1, t5, t9 , t13); // column 1
        QUARTERROUND(t2, t6, t10, t14); // column 2
        QUARTERROUND(t3, t7, t11, t15); // column 3
        QUARTERROUND(t0, t5, t10, t15); // diagonal 0
        QUARTERROUND(t1, t6, t11, t12); // diagonal 1
        QUARTERROUND(t2, t7, t8 , t13); // diagonal 2
        QUARTERROUND(t3, t4, t9 , t14); // diagonal 3
    }
    out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
    out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
    out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
    out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}

static void chacha20_init_key(crypto_chacha_ctx *ctx, const u8 key[32])
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
}

static u8 chacha20_pool_byte(crypto_chacha_ctx *ctx)
{
    u32 pool_word = ctx->pool[ctx->pool_idx / 4];
    u8  pool_byte = pool_word >> (8*(ctx->pool_idx % 4));
    ctx->pool_idx++;
    return pool_byte;
}

// Fill the pool if needed, update the counters
static void chacha20_refill_pool(crypto_chacha_ctx *ctx)
{
    chacha20_rounds(ctx->pool, ctx->input);
    FOR (j, 0, 16) {
        ctx->pool[j] += ctx->input[j];
    }
    ctx->pool_idx = 0;
    ctx->input[12]++;
    if (ctx->input[12] == 0) {
        ctx->input[13]++;
    }
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
    // Wipe buffer
    volatile u32 *v_buffer = buffer;
    FOR (i, 0, 16) {
        v_buffer[i] = 0;
    }
}

void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                          const u8           key[32],
                          const u8           nonce[8])
{
    chacha20_init_key      (ctx, key);     // key
    crypto_chacha20_set_ctr(ctx, 0  );     // counter
    ctx->input[14] = load32_le(nonce + 0); // nonce
    ctx->input[15] = load32_le(nonce + 4); // nonce
}

void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                            const u8           key[32],
                            const u8           nonce[24])
{
    u8 derived_key[32];
    crypto_chacha20_H(derived_key, key, nonce);
    crypto_chacha20_init(ctx, derived_key, nonce + 16);
}

void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, u64 ctr)
{
    ctx->input[12] = ctr & 0xffffffff;
    ctx->input[13] = ctr >> 32;
    ctx->pool_idx  = 64;  // The random pool (re)starts empty
}

void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                             u8                *cipher_text,
                             const u8          *plain_text,
                             size_t             text_size)
{
    // Align ourselves with a block
    while (ctx->pool_idx % 64 != 0 && text_size > 0) {
        u8 stream = chacha20_pool_byte(ctx);
        u8 plain  = 0;
        if (plain_text != 0) {
            plain = *plain_text;
            plain_text++;
        }
        *cipher_text = stream ^ plain;
        text_size--;
        cipher_text++;
    }
    // Main processing by 64 byte chunks
    size_t nb_blocks = text_size / 64;
    size_t remainder = text_size % 64;
    FOR (i, 0, nb_blocks) {
        chacha20_refill_pool(ctx);
        u32 txt[16];
        FOR (j, 0, 16) {
            if (plain_text) {
                txt[j] = load32_le(plain_text);
                plain_text += 4;
            } else {
                txt[j] = 0;
            }
        }
        FOR (j, 0, 16) {
            store32_le(cipher_text + j * 4, ctx->pool[j] ^ txt[j]);
        }
        cipher_text += 64;
    }
    if (nb_blocks > 0) {
        ctx->pool_idx = 64;
    }
    // Remaining input, byte by byte
    FOR (i, 0, remainder) {
        if (ctx->pool_idx == 64) {
            chacha20_refill_pool(ctx);
        }
        u8 stream = chacha20_pool_byte(ctx);
        u8 plain  = 0;
        if (plain_text != 0) {
            plain = *plain_text;
            plain_text++;
        }
        *cipher_text = stream ^ plain;
        cipher_text++;
    }
}

void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
                            uint8_t *stream, size_t size)
{
    crypto_chacha20_encrypt(ctx, stream, 0, size);
}


/////////////////
/// Poly 1305 ///
/////////////////

// h = (h + c) * r
// preconditions:
//   ctx->h <= 7_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->c <= 1_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->r <=   0ffffffc_0ffffffc_0ffffffc_0fffffff
// Postcondition:
//   ctx->h <= 4_87ffffe4_8fffffe2_97ffffe0_9ffffffa
static void poly_block(crypto_poly1305_ctx *ctx)
{
    // s = h + c, without carry propagation
    const u64 s0 = ctx->h[0] + (u64)ctx->c[0]; // s0 <= 1_fffffffe
    const u64 s1 = ctx->h[1] + (u64)ctx->c[1]; // s1 <= 1_fffffffe
    const u64 s2 = ctx->h[2] + (u64)ctx->c[2]; // s2 <= 1_fffffffe
    const u64 s3 = ctx->h[3] + (u64)ctx->c[3]; // s3 <= 1_fffffffe
    const u64 s4 = ctx->h[4] + (u64)ctx->c[4]; // s4 <=   00000004

    // Local all the things!
    const u32 r0 = ctx->r[0];       // r0  <= 0fffffff
    const u32 r1 = ctx->r[1];       // r1  <= 0ffffffc
    const u32 r2 = ctx->r[2];       // r2  <= 0ffffffc
    const u32 r3 = ctx->r[3];       // r3  <= 0ffffffc
    const u32 rr0 = (r0 >> 2) * 5;  // rr0 <= 13fffffb // lose 2 bits...
    const u32 rr1 = (r1 >> 2) + r1; // rr1 <= 13fffffb // rr1 == (r1 >> 2) * 5
    const u32 rr2 = (r2 >> 2) + r2; // rr2 <= 13fffffb // rr1 == (r2 >> 2) * 5
    const u32 rr3 = (r3 >> 2) + r3; // rr3 <= 13fffffb // rr1 == (r3 >> 2) * 5

    // (h + c) * r, without carry propagation
    const u64 x0 = s0*r0 + s1*rr3 + s2*rr2 + s3*rr1 + s4*rr0;//<=97ffffe007fffff8
    const u64 x1 = s0*r1 + s1*r0  + s2*rr3 + s3*rr2 + s4*rr1;//<=8fffffe20ffffff6
    const u64 x2 = s0*r2 + s1*r1  + s2*r0  + s3*rr3 + s4*rr2;//<=87ffffe417fffff4
    const u64 x3 = s0*r3 + s1*r2  + s2*r1  + s3*r0  + s4*rr3;//<=7fffffe61ffffff2
    const u32 x4 = s4 * (r0 & 3); // ...recover 2 bits       //<=0000000000000018

    // partial reduction modulo 2^130 - 5
    const u32 u5 = x4 + (x3 >> 32); // u5 <= 7ffffffe
    const u64 u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
    const u64 u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
    const u64 u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
    const u64 u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
    const u64 u4 = (u3 >> 32)     + (u5 & 3);

    // Update the hash
    ctx->h[0] = u0 & 0xffffffff; // u0 <= 1_9ffffffa
    ctx->h[1] = u1 & 0xffffffff; // u1 <= 1_97ffffe0
    ctx->h[2] = u2 & 0xffffffff; // u2 <= 1_8fffffe2
    ctx->h[3] = u3 & 0xffffffff; // u3 <= 1_87ffffe4
    ctx->h[4] = u4;              // u4 <=          4
}

// (re-)initializes the input counter and input buffer
static void poly_clear_c(crypto_poly1305_ctx *ctx)
{
    ctx->c[0]  = 0;
    ctx->c[1]  = 0;
    ctx->c[2]  = 0;
    ctx->c[3]  = 0;
    ctx->c_idx = 0;
}

static void poly_take_input(crypto_poly1305_ctx *ctx, u8 input)
{
    size_t word = ctx->c_idx / 4;
    size_t byte = ctx->c_idx % 4;
    ctx->c[word] |= (u32)input << (byte * 8);
    ctx->c_idx++;
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const u8 key[32])
{
    // Initial hash is zero
    FOR (i, 0, 5) {
        ctx->h [i] = 0;
    }
    // add 2^130 to every input block
    ctx->c  [4] = 1;
    poly_clear_c(ctx);
    // load r and pad (r has some of its bits cleared)
    FOR (i, 0, 1) { ctx->r  [0] = load32_le(key           ) & 0x0fffffff; }
    FOR (i, 1, 4) { ctx->r  [i] = load32_le(key + i*4     ) & 0x0ffffffc; }
    FOR (i, 0, 4) { ctx->pad[i] = load32_le(key + i*4 + 16);              }
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const u8 *message, size_t message_size)
{
    // Align ourselves with a block
    while (ctx->c_idx % 16 != 0 && message_size > 0) {
        poly_take_input(ctx, *message);
        message++;
        message_size--;
    }
    if (ctx->c_idx == 16) {
        poly_block(ctx);
        poly_clear_c(ctx);
    }
    // Process the input blok by block
    size_t nb_blocks = message_size / 16;
    size_t remainder = message_size % 16;
    FOR (i, 0, nb_blocks) {
        ctx->c[0] = load32_le(message +  0);
        ctx->c[1] = load32_le(message +  4);
        ctx->c[2] = load32_le(message +  8);
        ctx->c[3] = load32_le(message + 12);
        poly_block(ctx);
        message += 16;
    }
    if (nb_blocks > 0) {
        poly_clear_c(ctx);
    }

    // Input the remaining bytes
    FOR (i, 0, remainder) {
        poly_take_input(ctx, message[i]);
    }
}

void crypto_poly1305_final(crypto_poly1305_ctx *ctx, u8 mac[16])
{
    // Process the last block (if any)
    if (ctx->c_idx != 0) {
        // move the final 1 according to remaining input length
        // (We may add less than 2^130 to the last input block)
        ctx->c[4] = 0;
        poly_take_input(ctx, 1);
        // one last hash update
        poly_block(ctx);
    }

    // check if we should subtract 2^130-5 by performing the
    // corresponding carry propagation.
    u64 u = 5;
    u += ctx->h[0];  u >>= 32;
    u += ctx->h[1];  u >>= 32;
    u += ctx->h[2];  u >>= 32;
    u += ctx->h[3];  u >>= 32;
    u += ctx->h[4];  u >>=  2;
    // now u indicates how many times we should subtract 2^130-5 (0 or 1)

    // store h + pad, minus 2^130-5 if u tells us to.
    u *= 5;
    u += (i64)(ctx->h[0]) + ctx->pad[0];  store32_le(mac     , u);  u >>= 32;
    u += (i64)(ctx->h[1]) + ctx->pad[1];  store32_le(mac +  4, u);  u >>= 32;
    u += (i64)(ctx->h[2]) + ctx->pad[2];  store32_le(mac +  8, u);  u >>= 32;
    u += (i64)(ctx->h[3]) + ctx->pad[3];  store32_le(mac + 12, u);

    crypto_wipe(ctx, sizeof(*ctx));
}

void crypto_poly1305(u8     mac[16],  const u8 *message,
                     size_t message_size, const u8  key[32])
{
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, key);
    crypto_poly1305_update(&ctx, message, message_size);
    crypto_poly1305_final (&ctx, mac);
}

////////////////
/// Blake2 b ///
////////////////
static const u64 iv[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

// increment the input offset
static void blake2b_incr(crypto_blake2b_ctx *ctx)
{
    u64   *x = ctx->input_offset;
    size_t y = ctx->input_idx;
    x[0] += y;
    if (x[0] < y) {
        x[1]++;
    }
}

static void blake2b_set_input(crypto_blake2b_ctx *ctx, u8 input)
{
    size_t word = ctx->input_idx / 8;
    size_t byte = ctx->input_idx % 8;
    ctx->input[word] |= (u64)input << (byte * 8);
    ctx->input_idx++;
}

static void blake2b_compress(crypto_blake2b_ctx *ctx, int is_last_block)
{
    static const u8 sigma[12][16] = {
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
        { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
        {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
        {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
        {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
        { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
        { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
        {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
        { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    };

    // init work vector
    u64 v0 = ctx->hash[0];  u64 v8  = iv[0];
    u64 v1 = ctx->hash[1];  u64 v9  = iv[1];
    u64 v2 = ctx->hash[2];  u64 v10 = iv[2];
    u64 v3 = ctx->hash[3];  u64 v11 = iv[3];
    u64 v4 = ctx->hash[4];  u64 v12 = iv[4] ^ ctx->input_offset[0];
    u64 v5 = ctx->hash[5];  u64 v13 = iv[5] ^ ctx->input_offset[1];
    u64 v6 = ctx->hash[6];  u64 v14 = iv[6] ^ is_last_block;
    u64 v7 = ctx->hash[7];  u64 v15 = iv[7];

    // mangle work vector
    uint64_t *input = ctx->input;
#define BLAKE2_G(v, a, b, c, d, x, y)                  \
    v##a += v##b + x;  v##d = rotr64(v##d ^ v##a, 32); \
    v##c += v##d;      v##b = rotr64(v##b ^ v##c, 24); \
    v##a += v##b + y;  v##d = rotr64(v##d ^ v##a, 16); \
    v##c += v##d;      v##b = rotr64(v##b ^ v##c, 63);
#define BLAKE2_ROUND(i)                                                 \
    BLAKE2_G(v, 0, 4,  8, 12, input[sigma[i][ 0]], input[sigma[i][ 1]]);\
    BLAKE2_G(v, 1, 5,  9, 13, input[sigma[i][ 2]], input[sigma[i][ 3]]);\
    BLAKE2_G(v, 2, 6, 10, 14, input[sigma[i][ 4]], input[sigma[i][ 5]]);\
    BLAKE2_G(v, 3, 7, 11, 15, input[sigma[i][ 6]], input[sigma[i][ 7]]);\
    BLAKE2_G(v, 0, 5, 10, 15, input[sigma[i][ 8]], input[sigma[i][ 9]]);\
    BLAKE2_G(v, 1, 6, 11, 12, input[sigma[i][10]], input[sigma[i][11]]);\
    BLAKE2_G(v, 2, 7,  8, 13, input[sigma[i][12]], input[sigma[i][13]]);\
    BLAKE2_G(v, 3, 4,  9, 14, input[sigma[i][14]], input[sigma[i][15]])

    BLAKE2_ROUND(0);  BLAKE2_ROUND(1);  BLAKE2_ROUND(2);  BLAKE2_ROUND(3);
    BLAKE2_ROUND(4);  BLAKE2_ROUND(5);  BLAKE2_ROUND(6);  BLAKE2_ROUND(7);
    BLAKE2_ROUND(8);  BLAKE2_ROUND(9);  BLAKE2_ROUND(0);  BLAKE2_ROUND(1);

    // update hash
    ctx->hash[0] ^= v0 ^ v8;
    ctx->hash[1] ^= v1 ^ v9;
    ctx->hash[2] ^= v2 ^ v10;
    ctx->hash[3] ^= v3 ^ v11;
    ctx->hash[4] ^= v4 ^ v12;
    ctx->hash[5] ^= v5 ^ v13;
    ctx->hash[6] ^= v6 ^ v14;
    ctx->hash[7] ^= v7 ^ v15;
}

static void blake2b_reset_input(crypto_blake2b_ctx *ctx)
{
    FOR(i, 0, 16) {
        ctx->input[i] = 0;
    }
    ctx->input_idx = 0;
}

static void blake2b_end_block(crypto_blake2b_ctx *ctx)
{
    if (ctx->input_idx == 128) {  // If buffer is full,
        blake2b_incr(ctx);        // update the input offset
        blake2b_compress(ctx, 0); // and compress the (not last) block
        blake2b_reset_input(ctx);
    }
}

static void blake2b_fill_block(crypto_blake2b_ctx *ctx, const u8 message[128])
{
    FOR (j, 0, 16) {
        ctx->input[j] = load64_le(message + j*8);
    }
}

void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                                 const u8           *key, size_t key_size)
{
    // initial hash
    FOR (i, 0, 8) {
        ctx->hash[i] = iv[i];
    }
    ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

    ctx->input_offset[0] = 0;         // begining of the input, no offset
    ctx->input_offset[1] = 0;         // begining of the input, no offset
    ctx->hash_size       = hash_size; // remember the hash size we want
    blake2b_reset_input(ctx);         // clear the input buffer

    // if there is a key, the first block is that key
    if (key_size > 0) {
        crypto_blake2b_update(ctx, key, key_size);
        ctx->input_idx = 128;
    }
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx)
{
    crypto_blake2b_general_init(ctx, 64, 0, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const u8 *message, size_t message_size)
{
    // Align ourselves with blocks
    while (ctx->input_idx % 128 != 0 && message_size > 0) {
        blake2b_set_input(ctx, *message);
        message++;
        message_size--;
    }

    // Process the input one block at a time
    size_t nb_blocks = message_size / 128;
    size_t remainder = message_size % 128;
    if (nb_blocks > 0) {
        // first block
        blake2b_end_block(ctx);
        blake2b_fill_block(ctx, message);
        message += 128;
        ctx->input_idx = 128;
        // subsequent blocks
        FOR (i, 0, nb_blocks - 1) {
            blake2b_incr(ctx);
            blake2b_compress(ctx, 0);
            blake2b_fill_block(ctx, message);
            message += 128;
        }
    }

    // Load the remainder
    if (remainder != 0) {
        blake2b_end_block(ctx);
    }
    FOR (i, 0, remainder) {
        blake2b_set_input(ctx, message[i]);
    }
}

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, u8 *hash)
{
    blake2b_incr(ctx);         // update the input offset
    blake2b_compress(ctx, -1); // compress the last block
    size_t nb_words  = ctx->hash_size / 8;
    FOR (i, 0, nb_words) {
        store64_le(hash + i*8, ctx->hash[i]);
    }
    FOR (i, nb_words * 8, ctx->hash_size) {
        hash[i] = (ctx->hash[i / 8] >> (8 * (i % 8))) & 0xff;
    }
    crypto_wipe(ctx, sizeof(*ctx));
}

void crypto_blake2b_general(u8       *hash   , size_t hash_size,
                            const u8 *key    , size_t key_size,
                            const u8 *message, size_t message_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, hash_size, key, key_size);
    crypto_blake2b_update(&ctx, message, message_size);
    crypto_blake2b_final(&ctx, hash);
}

void crypto_blake2b(u8 hash[64], const u8 *message, size_t message_size)
{
    crypto_blake2b_general(hash, 64, 0, 0, message, message_size);
}


////////////////
/// Argon2 i ///
////////////////
// references to R, Z, Q etc. come from the spec

// Argon2 operates on 1024 byte blocks.
typedef struct { u64 a[128]; } block;

static u32 min(u32 a, u32 b) { return a <= b ? a : b; }

// updates a blake2 hash with a 32 bit word, little endian.
static void blake_update_32(crypto_blake2b_ctx *ctx, u32 input)
{
    u8 buf[4];
    store32_le(buf, input);
    crypto_blake2b_update(ctx, buf, 4);
}

static void load_block(block *b, const u8 bytes[1024])
{
    FOR (i, 0, 128) {
        b->a[i] = load64_le(bytes + i*8);
    }
}

static void store_block(u8 bytes[1024], const block *b)
{
    FOR (i, 0, 128) {
        store64_le(bytes + i*8, b->a[i]);
    }
}

static void copy_block(block *o,const block*in){FOR(i,0,128) o->a[i] = in->a[i];}
static void  xor_block(block *o,const block*in){FOR(i,0,128) o->a[i]^= in->a[i];}

// Hash with a virtually unlimited digest size.
// Doesn't extract more entropy than the base hash function.
// Mainly used for filling a whole kilobyte block with pseudo-random bytes.
// (One could use a stream cipher with a seed hash as the key, but
//  this would introduce another dependency —and point of failure.)
static void extended_hash(u8       *digest, u32 digest_size,
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
static void g_rounds(block *work_block)
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

// The compression function G (copy version for the first pass)
static void g_copy(block *result, const block *x, const block *y)
{
    block tmp;
    copy_block(&tmp  , x   ); // tmp    = X
    xor_block (&tmp  , y   ); // tmp    = X ^ Y = R
    copy_block(result, &tmp); // result = R         (only difference with g_xor)
    g_rounds  (&tmp);         // tmp    = Z
    xor_block (result, &tmp); // result = R ^ Z
}

// The compression function G (xor version for subsequent passes)
static void g_xor(block *result, const block *x, const block *y)
{
    block tmp;
    copy_block(&tmp  , x   ); // tmp    = X
    xor_block (&tmp  , y   ); // tmp    = X ^ Y = R
    xor_block (result, &tmp); // result = R ^ old   (only difference with g_copy)
    g_rounds  (&tmp);         // tmp    = Z
    xor_block (result, &tmp); // result = R ^ old ^ Z
}

// unary version of the compression function.
// The missing argument is implied zero.
// Does the transformation in place.
static void unary_g(block *work_block)
{
    // work_block == R
    block tmp;
    copy_block(&tmp, work_block); // tmp        = R
    g_rounds(work_block);         // work_block = Z
    xor_block(work_block, &tmp);  // work_block = Z ^ R
}

// Argon2i uses a kind of stream cipher to determine which reference
// block it will take to synthesise the next block.  This context hold
// that stream's state.  (It's very similar to Chacha20.  The block b
// is anologous to Chacha's own pool)
typedef struct {
    block b;
    u32 pass_number;
    u32 slice_number;
    u32 nb_blocks;
    u32 nb_iterations;
    u32 ctr;
    u32 offset;
} gidx_ctx;

// The block in the context will determine array indices. To avoid
// timing attacks, it only depends on public information.  No looking
// at a previous block to seed the next.  This makes offline attacks
// easier, but timing attacks are the bigger threat in many settings.
static void gidx_refresh(gidx_ctx *ctx)
{
    // seed the begining of the block...
    ctx->b.a[0] = ctx->pass_number;
    ctx->b.a[1] = 0;  // lane number (we have only one)
    ctx->b.a[2] = ctx->slice_number;
    ctx->b.a[3] = ctx->nb_blocks;
    ctx->b.a[4] = ctx->nb_iterations;
    ctx->b.a[5] = 1;  // type: Argon2i
    ctx->b.a[6] = ctx->ctr;
    FOR (i, 7, 128) { ctx->b.a[i] = 0; } // ...then zero the rest out

    // Shuffle the block thus: ctx->b = G((G(ctx->b, zero)), zero)
    // (G "square" function), to get cheap pseudo-random numbers.
    unary_g(&(ctx->b));
    unary_g(&(ctx->b));
}

static void gidx_init(gidx_ctx *ctx,
                      u32 pass_number, u32 slice_number,
                      u32 nb_blocks,   u32 nb_iterations)
{
    ctx->pass_number   = pass_number;
    ctx->slice_number  = slice_number;
    ctx->nb_blocks     = nb_blocks;
    ctx->nb_iterations = nb_iterations;
    ctx->ctr           = 0;

    // Offset from the begining of the segment.  For the first slice
    // of the first pass, we start at the *third* block, so the offset
    // starts at 2, not 0.
    if (pass_number != 0 || slice_number != 0) {
        ctx->offset = 0;
    } else {
        ctx->offset = 2;
        ctx->ctr++;         // Compensates for missed lazy creation
        gidx_refresh(ctx);  // at the start of gidx_next()
    }
}

static u32 gidx_next(gidx_ctx *ctx)
{
    // lazily creates the offset block we need
    if (ctx->offset % 128 == 0) {
        ctx->ctr++;
        gidx_refresh(ctx);
    }
    u32 index  = ctx->offset % 128; // save index  for current call
    u32 offset = ctx->offset;       // save offset for current call
    ctx->offset++;                  // update offset for next call

    // Computes the area size.
    // Pass 0 : all already finished segments plus already constructed
    //          blocks in this segment
    // Pass 1+: 3 last segments plus already constructed
    //          blocks in this segment.  THE SPEC SUGGESTS OTHERWISE.
    //          I CONFORM TO THE REFERENCE IMPLEMENTATION.
    int first_pass  = ctx->pass_number == 0;
    u32 slice_size  = ctx->nb_blocks / 4;
    u32 nb_segments = first_pass ? ctx->slice_number : 3;
    u32 area_size   = nb_segments * slice_size + offset - 1;

    // Computes the starting position of the reference area.
    // CONTRARY TO WHAT THE SPEC SUGGESTS, IT STARTS AT THE
    // NEXT SEGMENT, NOT THE NEXT BLOCK.
    u32 next_slice = ((ctx->slice_number + 1) % 4) * slice_size;
    u32 start_pos  = first_pass ? 0 : next_slice;

    // Generate offset from J1 (no need for J2, there's only one lane)
    u64 j1         = ctx->b.a[index] & 0xffffffff; // pseudo-random number
    u64 x          = (j1 * j1)       >> 32;
    u64 y          = (area_size * x) >> 32;
    u64 z          = (area_size - 1) - y;
    return (start_pos + z) % ctx->nb_blocks;
}

// Main algorithm
void crypto_argon2i_general(u8       *hash,      u32 hash_size,
                            void     *work_area, u32 nb_blocks,
                            u32 nb_iterations,
                            const u8 *password,  u32 password_size,
                            const u8 *salt,      u32 salt_size,
                            const u8 *key,       u32 key_size,
                            const u8 *ad,        u32 ad_size)
{
    // work area seen as blocks (must be suitably aligned)
    block *blocks = (block*)work_area;
    {
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx);

        blake_update_32      (&ctx, 1            ); // p: number of threads
        blake_update_32      (&ctx, hash_size    );
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

        crypto_wipe(initial_hash,   72);
        crypto_wipe(hash_area   , 1024);
    }

    // Actual number of blocks
    nb_blocks -= nb_blocks % 4; // round down to 4 p (p == 1 thread)
    const u32 segment_size = nb_blocks / 4;

    // fill (then re-fill) the rest of the blocks
    FOR (pass_number, 0, nb_iterations) {
        int first_pass = pass_number == 0;

        FOR (segment, 0, 4) {
            gidx_ctx ctx;
            gidx_init(&ctx, pass_number, segment, nb_blocks, nb_iterations);

            // On the first segment of the first pass,
            // blocks 0 and 1 are already filled.
            // We use the offset to skip them.
            u32 start_offset  = first_pass && segment == 0 ? 2 : 0;
            u32 segment_start = segment * segment_size + start_offset;
            u32 segment_end   = (segment + 1) * segment_size;
            FOR (current_block, segment_start, segment_end) {
                u32 reference_block = gidx_next(&ctx);
                u32 previous_block  = current_block == 0
                                    ? nb_blocks - 1
                                    : current_block - 1;
                block *c = blocks + current_block;
                block *p = blocks + previous_block;
                block *r = blocks + reference_block;
                if (first_pass) { g_copy(c, p, r); }
                else            { g_xor (c, p, r); }
            }
        }
    }
    // hash the very last block with H' into the output hash
    u8 final_block[1024];
    store_block(final_block, blocks + (nb_blocks - 1));
    extended_hash(hash, hash_size, final_block, 1024);

    // wipe final block and work area
    crypto_wipe(final_block, 1024);
    volatile u64 *p = (u64*)work_area;
    FOR (i, 0, 128 * nb_blocks) {
        p[i] = 0;
    }
}

void crypto_argon2i(u8       *hash,      u32 hash_size,
                    void     *work_area, u32 nb_blocks,
                    u32 nb_iterations,
                    const u8 *password,  u32 password_size,
                    const u8 *salt,      u32 salt_size)
{
    crypto_argon2i_general(hash, hash_size,
                           work_area, nb_blocks, nb_iterations,
                           password, password_size,
                           salt    , salt_size,
                           0, 0, 0, 0);
}



////////////////////////////////////
/// Arithmetic modulo 2^255 - 19 ///
////////////////////////////////////
//  Taken from Supercop's ref10 implementation.
//  A bit bigger than TweetNaCl, over 4 times faster.

// field element
typedef i32 fe[10];

static void fe_0(fe h) {            FOR(i, 0, 10) h[i] = 0; }
static void fe_1(fe h) { h[0] = 1;  FOR(i, 1, 10) h[i] = 0; }

static void fe_copy(fe h,const fe f           ){FOR(i,0,10) h[i] =  f[i];      }
static void fe_neg (fe h,const fe f           ){FOR(i,0,10) h[i] = -f[i];      }
static void fe_add (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] + g[i];}
static void fe_sub (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] - g[i];}

static void fe_cswap(fe f, fe g, int b)
{
    FOR (i, 0, 10) {
        i32 x = (f[i] ^ g[i]) & -b;
        f[i] = f[i] ^ x;
        g[i] = g[i] ^ x;
    }
}

static void fe_carry(fe h, i64 t[10])
{
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;
    c9 = (t[9] + (i64) (1<<24)) >> 25; t[0] += c9 * 19; t[9] -= c9 * (1 << 25);
    c1 = (t[1] + (i64) (1<<24)) >> 25; t[2] += c1;      t[1] -= c1 * (1 << 25);
    c3 = (t[3] + (i64) (1<<24)) >> 25; t[4] += c3;      t[3] -= c3 * (1 << 25);
    c5 = (t[5] + (i64) (1<<24)) >> 25; t[6] += c5;      t[5] -= c5 * (1 << 25);
    c7 = (t[7] + (i64) (1<<24)) >> 25; t[8] += c7;      t[7] -= c7 * (1 << 25);
    c0 = (t[0] + (i64) (1<<25)) >> 26; t[1] += c0;      t[0] -= c0 * (1 << 26);
    c2 = (t[2] + (i64) (1<<25)) >> 26; t[3] += c2;      t[2] -= c2 * (1 << 26);
    c4 = (t[4] + (i64) (1<<25)) >> 26; t[5] += c4;      t[4] -= c4 * (1 << 26);
    c6 = (t[6] + (i64) (1<<25)) >> 26; t[7] += c6;      t[6] -= c6 * (1 << 26);
    c8 = (t[8] + (i64) (1<<25)) >> 26; t[9] += c8;      t[8] -= c8 * (1 << 26);
    FOR (i, 0, 10) { h[i] = t[i]; }
}

static void fe_frombytes(fe h, const u8 s[32])
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

static void fe_mul_small(fe h, const fe f, i32 g)
{
    i64 t[10];
    FOR(i, 0, 10) {
        t[i] = f[i] * (i64) g;
    }
    fe_carry(h, t);
}
static void fe_mul121666(fe h, const fe f) { fe_mul_small(h, f, 121666); }
static void fe_mul973324(fe h, const fe f) { fe_mul_small(h, f, 973324); }

static void fe_mul(fe h, const fe f, const fe g)
{
    // Everything is unrolled and put in temporary variables.
    // We could roll the loop, but that would make curve25519 twice as slow.
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

#define CARRY                                                             \
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;                           \
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 * (1 << 26); \
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 * (1 << 26); \
    c1 = (h1 + (i64) (1<<24)) >> 25; h2 += c1;      h1 -= c1 * (1 << 25); \
    c5 = (h5 + (i64) (1<<24)) >> 25; h6 += c5;      h5 -= c5 * (1 << 25); \
    c2 = (h2 + (i64) (1<<25)) >> 26; h3 += c2;      h2 -= c2 * (1 << 26); \
    c6 = (h6 + (i64) (1<<25)) >> 26; h7 += c6;      h6 -= c6 * (1 << 26); \
    c3 = (h3 + (i64) (1<<24)) >> 25; h4 += c3;      h3 -= c3 * (1 << 25); \
    c7 = (h7 + (i64) (1<<24)) >> 25; h8 += c7;      h7 -= c7 * (1 << 25); \
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 * (1 << 26); \
    c8 = (h8 + (i64) (1<<25)) >> 26; h9 += c8;      h8 -= c8 * (1 << 26); \
    c9 = (h9 + (i64) (1<<24)) >> 25; h0 += c9 * 19; h9 -= c9 * (1 << 25); \
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 * (1 << 26); \
    h[0] = h0;  h[1] = h1;  h[2] = h2;  h[3] = h3;  h[4] = h4;            \
    h[5] = h5;  h[6] = h6;  h[7] = h7;  h[8] = h8;  h[9] = h9;            \

    CARRY;
}

// we could use fe_mul() for this, but this is significantly faster
static void fe_sq(fe h, const fe f)
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

    CARRY;
}

// This could be simplified, but it would be slower
static void fe_invert(fe out, const fe z)
{
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

// This could be simplified, but it would be slower
void fe_pow22523(fe out, const fe z)
{
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

static void fe_tobytes(u8 s[32], const fe h)
{
    i32 t[10];
    FOR (i, 0, 10) {
        t[i] = h[i];
    }
    i32 q = (19 * t[9] + (((i32) 1) << 24)) >> 25;
    FOR (i, 0, 5) {
        q += t[2*i  ]; q >>= 26;
        q += t[2*i+1]; q >>= 25;
    }
    t[0] += 19 * q;

    i32 c0 = t[0] >> 26; t[1] += c0; t[0] -= c0 * (1 << 26);
    i32 c1 = t[1] >> 25; t[2] += c1; t[1] -= c1 * (1 << 25);
    i32 c2 = t[2] >> 26; t[3] += c2; t[2] -= c2 * (1 << 26);
    i32 c3 = t[3] >> 25; t[4] += c3; t[3] -= c3 * (1 << 25);
    i32 c4 = t[4] >> 26; t[5] += c4; t[4] -= c4 * (1 << 26);
    i32 c5 = t[5] >> 25; t[6] += c5; t[5] -= c5 * (1 << 25);
    i32 c6 = t[6] >> 26; t[7] += c6; t[6] -= c6 * (1 << 26);
    i32 c7 = t[7] >> 25; t[8] += c7; t[7] -= c7 * (1 << 25);
    i32 c8 = t[8] >> 26; t[9] += c8; t[8] -= c8 * (1 << 26);
    i32 c9 = t[9] >> 25;             t[9] -= c9 * (1 << 25);

    store32_le(s +  0, ((u32)t[0] >>  0) | ((u32)t[1] << 26));
    store32_le(s +  4, ((u32)t[1] >>  6) | ((u32)t[2] << 19));
    store32_le(s +  8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
    store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] <<  6));
    store32_le(s + 16, ((u32)t[5] >>  0) | ((u32)t[6] << 25));
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
    u8 s[32];
    fe_tobytes(s, f);
    return zerocmp32(s);
}

///////////////
/// X-25519 /// Taken from Supercop's ref10 implementation.
///////////////

static void trim_scalar(u8 s[32])
{
    s[ 0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

static void x25519_ladder(const fe x1, fe x2, fe z2, fe x3, fe z3,
                          const u8 scalar[32])
{
    // Montgomery ladder
    // In projective coordinates, to avoid divisons: x = X / Z
    // We don't care about the y coordinate, it's only 1 bit of information
    fe_1(x2);        fe_0(z2); // "zero" point
    fe_copy(x3, x1); fe_1(z3); // "one"  point
    int swap = 0;
    for (int pos = 254; pos >= 0; --pos) {
        // constant time conditional swap before ladder step
        int b = (scalar[pos / 8] >> (pos & 7)) & 1;
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
    // Note: after this swap, P3 == P2 + P1.
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
}

int crypto_x25519(u8       raw_shared_secret[32],
                  const u8 your_secret_key  [32],
                  const u8 their_public_key [32])
{
    // computes the scalar product
    fe x1;
    fe_frombytes(x1, their_public_key);

    // restrict the possible scalar values
    u8 e[32];
    FOR (i, 0, 32) {
        e[i] = your_secret_key[i];
    }
    trim_scalar(e);

    // computes the actual scalar product (the result is in x2 and z2)
    fe x2, z2, x3, z3;
    x25519_ladder(x1, x2, z2, x3, z3, e);

    // normalises the coordinates: x == X / Z
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(raw_shared_secret, x2);

    // Returns -1 if the input is all zero
    // (happens with some malicious public keys)
    return -1 - zerocmp32(raw_shared_secret);
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
// in extended projective coordinates.
// x = X/Z, y = Y/Z, T = XY/Z
typedef struct { fe X; fe Y; fe Z; fe T; } ge;

static void ge_from_xy(ge *p, const fe x, const fe y)
{
    FOR (i, 0, 10) {
        p->X[i] = x[i];
        p->Y[i] = y[i];
    }
    fe_1  (p->Z);
    fe_mul(p->T, x, y);
}

static void ge_tobytes(u8 s[32], const ge *h)
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
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116
    } ;
    static const fe sqrtm1 = {
        -32595792, -7943725, 9377950, 3500415, 12389472,
        -272473, -25146209, -2005654, 326686, 11406482
    } ;
    fe u, v, v3, vxx, check;
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);            // y^2
    fe_mul(v, u, d);
    fe_sub(u, u, h->Z);        // u = y^2-1
    fe_add(v, v, h->Z);        // v = dy^2+1

    fe_sq(v3, v);
    fe_mul(v3, v3, v);         // v3 = v^3
    fe_sq(h->X, v3);
    fe_mul(h->X, h->X, v);
    fe_mul(h->X, h->X, u);     // x = uv^7

    fe_pow22523(h->X, h->X);   // x = (uv^7)^((q-5)/8)
    fe_mul(h->X, h->X, v3);
    fe_mul(h->X, h->X, u);     // x = uv^3(uv^7)^((q-5)/8)

    fe_sq(vxx, h->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);     // vx^2-u
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u); // vx^2+u
        if (fe_isnonzero(check)) {
            return -1;
        }
        fe_mul(h->X, h->X, sqrtm1);
    }
    if (fe_isnegative(h->X) == (s[31] >> 7)) {
        fe_neg(h->X, h->X);
    }
    fe_mul(h->T, h->X, h->Y);
    return 0;
}

static void ge_add(ge *s, const ge *p, const ge *q)
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
    fe_mul(s->Z, f, g);  //  Z3 = F * G
    fe_mul(s->T, e, h);  //  T3 = E * H
}

// Performing the scalar multiplication directly in Twisted Edwards
// space woud be simpler, but also slower.  So we do it in Montgomery
// space instead.  The sign of the Y coordinate however gets lost in
// translation, so we use a dirty trick to recover it.
static void ge_scalarmult(ge *p, const ge *q, const u8 scalar[32])
{
    // sqrt(-486664)
    static const fe K = { 54885894, 25242303, 55597453,  9067496, 51808079,
                          33312638, 25456129, 14121551, 54921728,  3972023 };

    // convert q to montgomery format
    fe x1, y1, z1, x2, z2, x3, z3, t1, t2, t3, t4;
    fe_sub(z1, q->Z, q->Y);  fe_mul(z1, z1, q->X);  fe_invert(z1, z1);
    fe_add(t1, q->Z, q->Y);
    fe_mul(x1, q->X, t1  );  fe_mul(x1, x1, z1);
    fe_mul(y1, q->Z, t1  );  fe_mul(y1, y1, z1);  fe_mul(y1, K, y1);
    fe_1(z1); // implied in the ladder, needed to convert back.

    // montgomery scalarmult
    x25519_ladder(x1, x2, z2, x3, z3, scalar);

    // Recover the y coordinate (Katsuyuki Okeya & Kouichi Sakurai, 2001)
    // Note the shameless reuse of x1: (x1, y1, z1) will correspond to
    // what was originally (x2, z2).
    fe_mul(t1, x1, z2);    fe_add(t2, x2, t1);    fe_sub(t3, x2, t1);
    fe_sq (t3, t3);        fe_mul(t3, t3, x3);    fe_mul973324(t1, z2);
    fe_add(t2, t2, t1);    fe_mul(t4, x1, x2);    fe_add(t4, t4, z2);
    fe_mul(t2, t2, t4);    fe_mul(t1, t1, z2);    fe_sub(t2, t2, t1);
    fe_mul(t2, t2, z3);    fe_add(t1, y1, y1);    fe_mul(t1, t1, z2);
    fe_mul(t1, t1, z3);    fe_mul(x1, t1, x2);    fe_sub(y1, t2, t3);
    fe_mul(z1, t1, z2);

    // convert back to twisted edwards
    fe_sub(t1  , x1, z1);    fe_add(t2  , x1, z1);    fe_mul(x1  , K , x1);
    fe_mul(p->X, x1, t2);    fe_mul(p->Y, y1, t1);    fe_mul(p->Z, y1, t2);
    fe_mul(p->T, x1, t1);
}

static void ge_scalarmult_base(ge *p, const u8 scalar[32])
{
    // Calls the general ge_scalarmult() with the base point.
    // Other implementations use a precomputed table, but it
    // takes way too much code.
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

static void modL(u8 *r, i64 x[64])
{
    static const  u64 L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
    for (unsigned i = 63; i >= 32; i--) {
        i64 carry = 0;
        FOR (j, i-32, i-12) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * (1 << 8);
        }
        x[i-12] += carry;
        x[i] = 0;
    }
    i64 carry = 0;
    FOR(i, 0, 32) {
        x[i] += carry - (x[31] >> 4) * L[i];
        carry = x[i] >> 8;
        x[i] &= 255;
    }
    FOR(i, 0, 32) {
        x[i] -= carry * L[i];
    }
    FOR(i, 0, 32) {
        x[i+1] += x[i] >> 8;
        r[i  ]  = x[i] & 255;
    }
    crypto_wipe(x, 64 * 8);
}

static void reduce(u8 r[64])
{
    i64 x[64];
    FOR(i, 0, 64) {
        x[i] = (u64) r[i];
        r[i] = 0;
    }
    modL(r, x);
}

void crypto_sign_public_key(u8       public_key[32],
                            const u8 secret_key[32])
{
    u8 a[64];
    HASH(a, secret_key, 32);
    trim_scalar(a);
    ge A;
    ge_scalarmult_base(&A, a);
    ge_tobytes(public_key, &A);
}

void crypto_sign_init_first_pass(crypto_sign_ctx *ctx,
                                 const u8  secret_key[32],
                                 const u8  public_key[32])
{
    u8 *a      = ctx->buf;
    u8 *prefix = ctx->buf + 32;
    HASH(a, secret_key, 32);
    trim_scalar(a);

    if (public_key == 0) {
        crypto_sign_public_key(ctx->pk, secret_key);
    } else {
        FOR (i, 0, 32) {
            ctx->pk[i] = public_key[i];
        }
    }

    // Constructs the "random" nonce from the secret key and message.
    // An actual random number would work just fine, and would save us
    // the trouble of hashing the message twice.  If we did that
    // however, the user could fuck it up and reuse the nonce.
    HASH_INIT  (&(ctx->hash));
    HASH_UPDATE(&(ctx->hash), prefix , 32);
}

void crypto_sign_update(crypto_sign_ctx *ctx, const u8 *msg, size_t msg_size)
{
    HASH_UPDATE(&(ctx->hash), msg, msg_size);
}

void crypto_sign_init_second_pass(crypto_sign_ctx *ctx)
{
    u8 *r        = ctx->buf + 32;
    u8 *half_sig = ctx->buf + 64;
    HASH_FINAL(&(ctx->hash), r);
    reduce(r);

    // first half of the signature = "random" nonce times basepoint
    ge R;
    ge_scalarmult_base(&R, r);
    ge_tobytes(half_sig, &R);

    // Hash R, the public key, and the message together.
    // It cannot be done in parallel with the first hash.
    HASH_INIT  (&ctx->hash);
    HASH_UPDATE(&ctx->hash, half_sig, 32);
    HASH_UPDATE(&ctx->hash, ctx->pk , 32);
}

void crypto_sign_final(crypto_sign_ctx *ctx, u8 signature[64])
{
    u8 *a        = ctx->buf;
    u8 *r        = ctx->buf + 32;
    u8 *half_sig = ctx->buf + 64;
    u8 h_ram[64];
    HASH_FINAL(&(ctx->hash), h_ram);
    reduce(h_ram);  // reduce the hash modulo L

    i64 s[64]; // s = r + h_ram * a
    FOR (i,  0, 32) { s[i] = (u64) r[i]; }
    FOR (i, 32, 64) { s[i] = 0;          }
    FOR (i,  0, 32) {
        FOR (j, 0, 32) {
            s[i+j] += h_ram[i] * (u64) a[j];
        }
    }
    FOR (i, 0, 32) {
        signature[i] = half_sig[i];
    }
    modL(signature + 32, s);  // second half of the signature = s

    crypto_wipe(ctx, sizeof(*ctx));
    crypto_wipe(h_ram, 64);
}

void crypto_sign(u8        signature[64],
                 const u8  secret_key[32],
                 const u8  public_key[32],
                 const u8 *message, size_t message_size)
{
    crypto_sign_ctx ctx;
    crypto_sign_init_first_pass (&ctx, secret_key, public_key);
    crypto_sign_update          (&ctx, message, message_size);
    crypto_sign_init_second_pass(&ctx);
    crypto_sign_update          (&ctx, message, message_size);
    crypto_sign_final           (&ctx, signature);
}

int crypto_check_public_key(const u8 public_key[32])
{
    ge A; // wasted result.
    return ge_frombytes_neg(&A, public_key);
}

void crypto_check_init(crypto_check_ctx *ctx,
                      const u8 signature[64],
                      const u8 public_key[32])
{
    FOR (i, 0, 64) { ctx->sig[i] = signature [i]; }
    FOR (i, 0, 32) { ctx->pk [i] = public_key[i]; }
    HASH_INIT  (&(ctx->hash));
    HASH_UPDATE(&(ctx->hash), signature , 32);
    HASH_UPDATE(&(ctx->hash), public_key, 32);
}

void crypto_check_update(crypto_check_ctx *ctx, const u8 *msg, size_t msg_size)
{
    HASH_UPDATE(&(ctx->hash), msg , msg_size);
}

int crypto_check_final(crypto_check_ctx *ctx)
{
    ge p, sB, diff, A;
    u8 h_ram[64], R_check[32];
    if (ge_frombytes_neg(&A, ctx->pk)) {       // -A
        return -1;
    }
    HASH_FINAL(&(ctx->hash), h_ram);
    reduce(h_ram);
    ge_scalarmult(&p, &A, h_ram);              // p    = -A*h_ram
    ge_scalarmult_base(&sB, ctx->sig + 32);
    ge_add(&diff, &p, &sB);                    // diff = s - A*h_ram
    ge_tobytes(R_check, &diff);
    return crypto_verify32(ctx->sig, R_check); // R == s - A*h_ram ? OK : fail
}

int crypto_check(const u8  signature[64],
                 const u8  public_key[32],
                 const u8 *message, size_t message_size)
{
    crypto_check_ctx ctx;
    crypto_check_init(&ctx, signature, public_key);
    crypto_check_update(&ctx, message, message_size);
    return crypto_check_final(&ctx);
}

////////////////////
/// Key exchange ///
////////////////////
int crypto_key_exchange(u8       shared_key[32],
                        const u8 your_secret_key [32],
                        const u8 their_public_key[32])
{
    static const u8 zero[16] = {0};
    u8 raw_shared_secret[32];
    int status = crypto_x25519(raw_shared_secret,
                               your_secret_key, their_public_key);
    crypto_chacha20_H(shared_key, raw_shared_secret, zero);
    return status;
}

////////////////////////////////
/// Authenticated encryption ///
////////////////////////////////
void crypto_lock_init(crypto_lock_ctx *ctx, const u8 key[32], const u8 nonce[24])
{
    u8 auth_key[32];
    crypto_chacha20_x_init(&(ctx->chacha), key, nonce);
    crypto_chacha20_stream(&(ctx->chacha), auth_key, 32);
    crypto_poly1305_init  (&(ctx->poly  ), auth_key);
    crypto_wipe(auth_key, 32);
}

void crypto_lock_encrypt(crypto_lock_ctx *ctx, u8 *cipher_text,
                         const u8 *plain_text, size_t text_size)
{
    crypto_chacha20_encrypt(&(ctx->chacha), cipher_text, plain_text, text_size);
}

void crypto_lock_auth(crypto_lock_ctx *ctx, const u8 *msg, size_t msg_size)
{
    crypto_poly1305_update(&(ctx->poly), msg, msg_size);
}

void crypto_lock_update(crypto_lock_ctx *ctx, u8 *cipher_text,
                        const u8 *plain_text, size_t text_size)
{
    crypto_lock_encrypt(ctx, cipher_text, plain_text, text_size);
    crypto_lock_auth   (ctx, cipher_text, text_size);
}

void crypto_lock_final(crypto_lock_ctx *ctx, u8 mac[16])
{
    crypto_poly1305_final(&(ctx->poly), mac);
}

void crypto_unlock_update(crypto_lock_ctx *ctx, u8 *plain_text,
                          const u8 *cipher_text, size_t text_size)
{
    crypto_lock_auth   (ctx, cipher_text, text_size);
    crypto_lock_encrypt(ctx, plain_text, cipher_text, text_size);
}

int crypto_unlock_final(crypto_lock_ctx *ctx, const u8 mac[16])
{
    u8 real_mac[16];
    crypto_lock_final(ctx, real_mac);
    int mismatch = crypto_verify16(real_mac, mac);
    crypto_wipe(real_mac, 16);
    return mismatch;
}

void crypto_aead_lock(u8        mac[16],
                      u8       *cipher_text,
                      const u8  key[32],
                      const u8  nonce[24],
                      const u8 *ad        , size_t ad_size,
                      const u8 *plain_text, size_t text_size)
{
    crypto_lock_ctx ctx;
    crypto_lock_init   (&ctx, key, nonce);
    // authenticate additional data first, to allow overlapping buffers
    crypto_lock_auth   (&ctx, ad, ad_size);
    crypto_lock_update (&ctx, cipher_text, plain_text, text_size);
    crypto_lock_final  (&ctx, mac);
    crypto_wipe(&(ctx.chacha), sizeof(ctx.chacha));
}

int crypto_aead_unlock(u8       *plain_text,
                       const u8  key[32],
                       const u8  nonce[24],
                       const u8  mac[16],
                       const u8 *ad         , size_t ad_size,
                       const u8 *cipher_text, size_t text_size)
{
    crypto_lock_ctx ctx;
    crypto_lock_init   (&ctx, key, nonce);
    crypto_lock_auth   (&ctx, ad, ad_size);
    crypto_lock_auth   (&ctx, cipher_text, text_size);
    if (crypto_unlock_final  (&ctx, mac)) {
        return -1; // reject forgeries before wasting our time decrypting
    }
    crypto_lock_encrypt(&ctx, plain_text, cipher_text, text_size);
    crypto_wipe(&(ctx.chacha), sizeof(ctx.chacha));
    return 0;
}

void crypto_lock(u8        mac[16],
                 u8       *cipher_text,
                 const u8  key[32],
                 const u8  nonce[24],
                 const u8 *plain_text, size_t text_size)
{
    crypto_aead_lock(mac, cipher_text, key, nonce, 0, 0, plain_text, text_size);
}

int crypto_unlock(u8       *plain_text,
                  const u8  key[32],
                  const u8  nonce[24],
                  const u8  mac[16],
                  const u8 *cipher_text, size_t text_size)
{
    return crypto_aead_unlock(plain_text, key, nonce, mac, 0, 0,
                              cipher_text, text_size);
}
