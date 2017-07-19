#include "sha512.h"

#define FOR(i, min, max) for (size_t i = min; i < max; i++)
typedef uint8_t u8;
typedef uint64_t u64;

static u64 rot(u64 x, int c       ) { return (x >> c) | (x << (64 - c));   }
static u64 ch (u64 x, u64 y, u64 z) { return (x & y) ^ (~x & z);           }
static u64 maj(u64 x, u64 y, u64 z) { return (x & y) ^ ( x & z) ^ (y & z); }
static u64 big_sigma0(u64 x) { return rot(x, 28) ^ rot(x, 34) ^ rot(x, 39); }
static u64 big_sigma1(u64 x) { return rot(x, 14) ^ rot(x, 18) ^ rot(x, 41); }
static u64 lit_sigma0(u64 x) { return rot(x,  1) ^ rot(x,  8) ^ (x >> 7);   }
static u64 lit_sigma1(u64 x) { return rot(x, 19) ^ rot(x, 61) ^ (x >> 6);   }

static const u64 K[80] = {
    0x428a2f98d728ae22,0x7137449123ef65cd,0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc,
    0x3956c25bf348b538,0x59f111f1b605d019,0x923f82a4af194f9b,0xab1c5ed5da6d8118,
    0xd807aa98a3030242,0x12835b0145706fbe,0x243185be4ee4b28c,0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,0x80deb1fe3b1696b1,0x9bdc06a725c71235,0xc19bf174cf692694,
    0xe49b69c19ef14ad2,0xefbe4786384f25e3,0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,0x4a7484aa6ea6e483,0x5cb0a9dcbd41fbd4,0x76f988da831153b5,
    0x983e5152ee66dfab,0xa831c66d2db43210,0xb00327c898fb213f,0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,0xd5a79147930aa725,0x06ca6351e003826f,0x142929670a0e6e70,
    0x27b70a8546d22ffc,0x2e1b21385c26c926,0x4d2c6dfc5ac42aed,0x53380d139d95b3df,
    0x650a73548baf63de,0x766a0abb3c77b2a8,0x81c2c92e47edaee6,0x92722c851482353b,
    0xa2bfe8a14cf10364,0xa81a664bbc423001,0xc24b8b70d0f89791,0xc76c51a30654be30,
    0xd192e819d6ef5218,0xd69906245565a910,0xf40e35855771202a,0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,0x1e376c085141ab53,0x2748774cdf8eeb99,0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb,0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,0x78a5636f43172f60,0x84c87814a1f0ab72,0x8cc702081a6439ec,
    0x90befffa23631e28,0xa4506cebde82bde9,0xbef9a3f7b2c67915,0xc67178f2e372532b,
    0xca273eceea26619c,0xd186b8c721c0c207,0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178,
    0x06f067aa72176fba,0x0a637dc5a2c898a6,0x113f9804bef90dae,0x1b710b35131c471b,
    0x28db77f523047d84,0x32caab7b40c72493,0x3c9ebe0a15c9bebc,0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,0x597f299cfc657e2a,0x5fcb6fab3ad6faec,0x6c44198c4a475817
};

static void sha512_compress(crypto_sha512_ctx *ctx)
{
    u64 w[80];
    FOR(i,  0, 16) { w[i] = ctx->m[i]; }
    FOR(i, 16, 80) { w[i] = (lit_sigma1(w[i- 2]) + w[i- 7] +
                             lit_sigma0(w[i-15]) + w[i-16]); }

    u64 a = ctx->h[0];    u64 b = ctx->h[1];
    u64 c = ctx->h[2];    u64 d = ctx->h[3];
    u64 e = ctx->h[4];    u64 f = ctx->h[5];
    u64 g = ctx->h[6];    u64 h = ctx->h[7];
    FOR(i, 0, 80) {
        u64 t1 = big_sigma1(e) + ch (e, f, g) + h + K[i] + w[i];
        u64 t2 = big_sigma0(a) + maj(a, b, c);
        h = g;  g = f;  f = e;  e = d  + t1;
        d = c;  c = b;  b = a;  a = t1 + t2;
    }
    ctx->h[0] += a;    ctx->h[1] += b;
    ctx->h[2] += c;    ctx->h[3] += d;
    ctx->h[4] += e;    ctx->h[5] += f;
    ctx->h[6] += g;    ctx->h[7] += h;
}

static void set_input(crypto_sha512_ctx *ctx, u8 input)
{
    ctx->m[ctx->m_index / 8] |= (u64)input << (8 * (7 - (ctx->m_index % 8)));
}

static void reset_input(crypto_sha512_ctx *ctx)
{
    FOR(i, 0, 16) { ctx->m[i] = 0; }
    ctx->m_index = 0;
}

// increment a 128-bit "word".
static void incr(u64 x[2], u64 y)
{
    x[1] += y;                 // increment the low word
    if (x[1] < y) { x[0]++; }  // handle overflow
}

void crypto_sha512_init(crypto_sha512_ctx *ctx)
{
    ctx->h[0] = 0x6a09e667f3bcc908;
    ctx->h[1] = 0xbb67ae8584caa73b;
    ctx->h[2] = 0x3c6ef372fe94f82b;
    ctx->h[3] = 0xa54ff53a5f1d36f1;
    ctx->h[4] = 0x510e527fade682d1;
    ctx->h[5] = 0x9b05688c2b3e6c1f;
    ctx->h[6] = 0x1f83d9abfb41bd6b;
    ctx->h[7] = 0x5be0cd19137e2179;
    ctx->m_size[0] = 0;
    ctx->m_size[1] = 0;
    reset_input(ctx);
}

void crypto_sha512_update(crypto_sha512_ctx *ctx, const u8 *in, size_t inlen)
{
    FOR (i, 0, inlen) {
        // The buffer is assumed not full.  We add one input byte.
        set_input(ctx, in[i]);
        ctx->m_index++;

        // If we just filled the buffer, we compress it.
        if (ctx->m_index == 128) {
            incr(ctx->m_size, 1024); // size is in bits
            sha512_compress(ctx);
            reset_input(ctx);
        }
    }
}

void crypto_sha512_final(crypto_sha512_ctx *ctx, u8 out[64])
{
    incr(ctx->m_size, ctx->m_index * 8); // size is in bits
    set_input(ctx, 128);                 // padding

    // compress penultimate block (if any)
    if (ctx->m_index > 111) {
        sha512_compress(ctx);
        reset_input(ctx);
    }
    // compress last block
    ctx->m[14] = ctx->m_size[0];
    ctx->m[15] = ctx->m_size[1];
    sha512_compress(ctx);

    // copy hash to output (big endian)
    FOR (i, 0, 8) {
        FOR (j, 0, 8) {
            out[8*i + 7 - j] = (ctx->h[i] >> (8*j)) & 255;
        }
    }
}

void crypto_sha512(u8 *out, const u8 *m, size_t n)
{
    crypto_sha512_ctx ctx;
    crypto_sha512_init  (&ctx);
    crypto_sha512_update(&ctx, m, n);
    crypto_sha512_final (&ctx, out);
}
