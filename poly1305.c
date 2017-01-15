// Taken from tweetNaCl

#include "poly1305.h"

static void poly1305_add(uint32_t h[17], const uint8_t c[17])
{
    uint32_t u = 0;
    for (int j = 0; j < 17; j++) {
        u     += h[j] + c[j];
        h[j]   = u & 255;
        u    >>= 8;
    }
}

static uint32_t poly1305_carry(uint32_t h[17], uint32_t carry)
{
    for (int i = 0; i < 16; i++) {
      carry  += h[i];
      h[i]    = carry & 255;
      carry >>= 8;
    }
    return carry + h[16];
}

static void poly1305_block(crypto_poly1305_ctx *ctx)
{
    poly1305_add(ctx->h, ctx->c);
    uint32_t x[17];
    for (int i = 0; i < 17; i++) {
        x[i] = 0;
        for (int j = 0    ; j < i + 1; j++)
            x[i] += ctx->h[j] * ctx->r[i - j];
        for (int j = i + 1; j < 17   ; j++)
            x[i] += ctx->h[j] * 320 * ctx->r[i + 17 - j];
    }
    for (int i = 0; i < 17; i++)
        ctx->h[i] = x[i];

    uint32_t u = poly1305_carry(ctx->h, 0           ); ctx->h[16] = u & 3;
    ctx->h[16] = poly1305_carry(ctx->h, 5 * (u >> 2));
}


void
crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32])
{
    for (int i = 0; i < 17; i++)
        ctx->h[i] = 0;
    for (int i = 0; i < 16; i++) {
        ctx->r  [i] = key[i     ];
        ctx->pad[i] = key[i + 16];
    }
    ctx->r[16] = 0;
    ctx->r[3]  &= 0x0f;  ctx->r[4]  &= 0xfc;
    ctx->r[7]  &= 0x0f;  ctx->r[8]  &= 0xfc;
    ctx->r[11] &= 0x0f;  ctx->r[12] &= 0xfc;
    ctx->r[15] &= 0x0f;
    ctx->c[16]   = 1;
    ctx->c_index = 0;
}

void
crypto_poly1305_update(crypto_poly1305_ctx *ctx, const uint8_t *m, size_t bytes)
{
    while (bytes > 0) {
        if (ctx->c_index == 16) {
            poly1305_block(ctx);
            ctx->c_index = 0;
        }
        ctx->c[ctx->c_index] = *m;
        ctx->c_index++;
        m++;
        bytes--;
    }
}

void
crypto_poly1305_finish(crypto_poly1305_ctx *ctx, uint8_t mac[16])
{
    // compute last block
    ctx->c[ctx->c_index] = 1;
    for (int i = ctx->c_index + 1; i < 17; i++)
        ctx->c[i] = 0;
    poly1305_block(ctx);

    // save h
    uint32_t g[17];
    for (int i = 0; i < 17; i++)  g[i]  = ctx->h[i];

    // finalise
    static const uint8_t minusp[17] = {5,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,252};
    poly1305_add(ctx->h, minusp);
    uint32_t s = -(ctx->h[16] >> 7);
    for (int i = 0; i < 17; i++)  ctx->h[i] ^= s & (g[i] ^ ctx->h[i]);
    for (int i = 0; i < 16; i++)  ctx->c[i]  = ctx->pad[i];
    ctx->c[16] = 0;
    poly1305_add(ctx->h, ctx->c);

    // copy mac
    for (int i = 0; i < 16; i++)  mac[i] = ctx->h[i];
}

void
crypto_poly1305_auth(uint8_t        mac[16],
                     const uint8_t *m,
                     size_t         m_size,
                     const uint8_t  key[32])
{
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, key);
    crypto_poly1305_update(&ctx, m, m_size);
    crypto_poly1305_finish(&ctx, mac);
}

int
crypto_poly1305_verify(const uint8_t mac1[16], const uint8_t mac2[16]) {
    unsigned diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (mac1[i] ^ mac2[i]);
    }
    return diff;
}
