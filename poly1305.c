#include "poly1305.h"

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
