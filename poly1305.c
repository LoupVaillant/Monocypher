// Ripped of from the poly-donna-32 implementation.
// Multiplies 32 bits operands into 64 bits results,
// Adds       64 bits operands into 64 bits results.

// Makes no attempt to securely erase anything.

#include "poly1305.h"

#define block_size 16

static uint32_t
load32_le(const uint8_t s[4])
{
    // Portable, slow way.
    return s[0]
        | (s[1] <<  8)
        | (s[2] << 16)
        | (s[3] << 24);
}

static void
store32_le(uint8_t output[4], uint32_t input)
{
    // Portable, slow way.
    output[0] =  input        & 0xff;
    output[1] = (input >>  8) & 0xff;
    output[2] = (input >> 16) & 0xff;
    output[3] = (input >> 24) & 0xff;
}

static void
crypto_poly1305_blocks(crypto_poly1305_ctx *ctx, const uint8_t *m, size_t bytes)
{
    const uint32_t hibit = (ctx->final) ? 0 : (1UL << 24); // 1 << 128
    const uint32_t r0    = ctx->r[0];
    const uint32_t r1    = ctx->r[1];
    const uint32_t r2    = ctx->r[2];
    const uint32_t r3    = ctx->r[3];
    const uint32_t r4    = ctx->r[4];
    const uint32_t s1    = r1 * 5;
    const uint32_t s2    = r2 * 5;
    const uint32_t s3    = r3 * 5;
    const uint32_t s4    = r4 * 5;

    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];

    while (bytes >= block_size) {
        // h += m[i]
        h0 += (load32_le(m+ 0)     ) & 0x3ffffff;
        h1 += (load32_le(m+ 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m+ 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m+ 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m+12) >> 8) | hibit;

        // h *= r
        uint64_t d0 =
            ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) +
            ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        uint64_t d1 =
            ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) +
            ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        uint64_t d2 =
            ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) +
            ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        uint64_t d3 =
            ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) +
            ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        uint64_t d4 =
            ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) +
            ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        // (partial) h %= p
        uint32_t      c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;      c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;      c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;      c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;      c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5;  c =           (h0 >> 26); h0 =           h0 & 0x3ffffff;
        h1 += c;

        m     += block_size;
        bytes -= block_size;
    }

    ctx->h[0] = h0;
    ctx->h[1] = h1;
    ctx->h[2] = h2;
    ctx->h[3] = h3;
    ctx->h[4] = h4;
}

void
crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32])
{
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    ctx->r[0] = (load32_le(&key[ 0])     ) & 0x3ffffff;
    ctx->r[1] = (load32_le(&key[ 3]) >> 2) & 0x3ffff03;
    ctx->r[2] = (load32_le(&key[ 6]) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (load32_le(&key[ 9]) >> 6) & 0x3f03fff;
    ctx->r[4] = (load32_le(&key[12]) >> 8) & 0x00fffff;

    /* h = 0 */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    /* save pad for later */
    ctx->pad[0] = load32_le(&key[16]);
    ctx->pad[1] = load32_le(&key[20]);
    ctx->pad[2] = load32_le(&key[24]);
    ctx->pad[3] = load32_le(&key[28]);

    ctx->leftover = 0;
    ctx->final    = 0;
}

void
crypto_poly1305_update(crypto_poly1305_ctx *ctx, const uint8_t *m, size_t bytes)
{
    // handle leftover
    if (ctx->leftover) {
        size_t want = (block_size - ctx->leftover);
        if (want > bytes) {
            want = bytes;
        }
        for (size_t i = 0; i < want; i++) {
            ctx->buffer[ctx->leftover + i] = m[i];
        }
        bytes -= want;
        m += want;
        ctx->leftover += want;
        if (ctx->leftover < block_size) {
            return;
        }
        crypto_poly1305_blocks(ctx, ctx->buffer, block_size);
        ctx->leftover = 0;
    }

    // process full blocks
    if (bytes >= block_size) {
        size_t want = (bytes & ~(block_size - 1));
        crypto_poly1305_blocks(ctx, m, want);
        m += want;
        bytes -= want;
    }

    // store leftover
    if (bytes) {
        for (size_t i = 0; i < bytes; i++) {
            ctx->buffer[ctx->leftover + i] = m[i];
        }
        ctx->leftover += bytes;
    }
}

void
crypto_poly1305_finish(crypto_poly1305_ctx *ctx, uint8_t mac[16])
{
    // process the remaining block
    if (ctx->leftover > 0) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < block_size; i++)
            ctx->buffer[i] = 0;
        ctx->final = 1;
        crypto_poly1305_blocks(ctx, ctx->buffer, block_size);
    }

    // fully carry h
    uint32_t h0 = ctx->h[0];
    uint32_t h1 = ctx->h[1];
    uint32_t h2 = ctx->h[2];
    uint32_t h3 = ctx->h[3];
    uint32_t h4 = ctx->h[4];

    uint32_t     c = h1 >> 26; h1 = h1 & 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
    h1 +=     c;

    // compute h - p
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1UL << 26);

    // if (h >= p) { h -= p; } // h %= p;
    // without branches, to avoid timing attacks.
    uint32_t mask = (g4 >> ((sizeof(uint32_t) * 8) - 1)) - 1;
    g0  &= mask;
    g1  &= mask;
    g2  &= mask;
    g3  &= mask;
    g4  &= mask;
    mask = ~mask;
    h0   = (h0 & mask) | g0;
    h1   = (h1 & mask) | g1;
    h2   = (h2 & mask) | g2;
    h3   = (h3 & mask) | g3;
    h4   = (h4 & mask) | g4;

    // h %= 2^128
    h0 = ((h0      ) | (h1 << 26));
    h1 = ((h1 >>  6) | (h2 << 20));
    h2 = ((h2 >> 12) | (h3 << 14));
    h3 = ((h3 >> 18) | (h4 <<  8));

    // mac = (h + pad) % (2^128)
    uint64_t f;
    f = (uint64_t)h0 + ctx->pad[0]            ; h0 = (uint32_t)f;
    f = (uint64_t)h1 + ctx->pad[1] + (f >> 32); h1 = (uint32_t)f;
    f = (uint64_t)h2 + ctx->pad[2] + (f >> 32); h2 = (uint32_t)f;
    f = (uint64_t)h3 + ctx->pad[3] + (f >> 32); h3 = (uint32_t)f;

    store32_le(mac +  0, h0);
    store32_le(mac +  4, h1);
    store32_le(mac +  8, h2);
    store32_le(mac + 12, h3);
}

void
crypto_poly1305_auth(uint8_t        mac[16],
                     const uint8_t *m,
                     size_t         msg_length,
                     const uint8_t  key[32])
{
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, key);
    crypto_poly1305_update(&ctx, m, msg_length);
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
