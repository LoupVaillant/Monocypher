// Monocypher version __git__
//
// This file is dual-licensed.  Choose whichever licence you want from
// the two licences listed below.
//
// The first licence is a regular 2-clause BSD licence.  The second licence
// is the CC-0 from Creative Commons. It is intended to release Monocypher
// to the public domain.  The BSD licence serves as a fallback option.
//
// SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
//
// ------------------------------------------------------------------------
//
// Copyright (c) 2017-2020, Loup Vaillant
// All rights reserved.
//
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the
//    distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// ------------------------------------------------------------------------
//
// Written in 2017-2020 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#include "monocypher.h"

/////////////////
/// Utilities ///
/////////////////
#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define COPY(dst, src, size)       FOR(i, 0, size) (dst)[i] = (src)[i]
#define ZERO(buf, size)            FOR(i, 0, size) (buf)[i] = 0
#define WIPE_CTX(ctx)              crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)        crypto_wipe(buffer, sizeof(buffer))
#define MIN(a, b)                  ((a) <= (b) ? (a) : (b))
#define MAX(a, b)                  ((a) >= (b) ? (a) : (b))
#define ALIGN(x, block_size)       ((~(x) + 1) & ((block_size) - 1))
typedef int8_t   i8;
typedef uint8_t  u8;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

static const u8 zero[128] = {0};

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
    store32_le(out    , (u32)in );
    store32_le(out + 4, in >> 32);
}

static void load32_le_buf (u32 *dst, const u8 *src, size_t size) {
    FOR(i, 0, size) { dst[i] = load32_le(src + i*4); }
}
static void load64_le_buf (u64 *dst, const u8 *src, size_t size) {
    FOR(i, 0, size) { dst[i] = load64_le(src + i*8); }
}
static void store32_le_buf(u8 *dst, const u32 *src, size_t size) {
    FOR(i, 0, size) { store32_le(dst + i*4, src[i]); }
}
static void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
    FOR(i, 0, size) { store64_le(dst + i*8, src[i]); }
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
static u64 x32(const u8 a[32],const u8 b[32]){return x16(a,b)| x16(a+16, b+16);}
static u64 x64(const u8 a[64],const u8 b[64]){return x32(a,b)| x32(a+32, b+32);}
int crypto_verify16(const u8 a[16], const u8 b[16]){ return neq0(x16(a, b)); }
int crypto_verify32(const u8 a[32], const u8 b[32]){ return neq0(x32(a, b)); }
int crypto_verify64(const u8 a[64], const u8 b[64]){ return neq0(x64(a, b)); }

static int zerocmp32(const u8 p[32])
{
    return crypto_verify32(p, zero);
}

void crypto_wipe(void *secret, size_t size)
{
    volatile u8 *v_secret = (u8*)secret;
    ZERO(v_secret, size);
}

/////////////////
/// Chacha 20 ///
/////////////////
#define QUARTERROUND(a, b, c, d)     \
    a += b;  d = rotl32(d ^ a, 16);  \
    c += d;  b = rotl32(b ^ c, 12);  \
    a += b;  d = rotl32(d ^ a,  8);  \
    c += d;  b = rotl32(b ^ c,  7)

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

static void chacha20_init_key(u32 block[16], const u8 key[32])
{
    load32_le_buf(block  , (const u8*)"expand 32-byte k", 4); // constant
    load32_le_buf(block+4, key                          , 8); // key
}

static u64 chacha20_core(u32 input[16], u8 *cipher_text, const u8 *plain_text,
                         size_t text_size)
{
    // Whole blocks
    u32    pool[16];
    size_t nb_blocks = text_size >> 6;
    FOR (i, 0, nb_blocks) {
        chacha20_rounds(pool, input);
        if (plain_text != 0) {
            FOR (j, 0, 16) {
                u32 p = pool[j] + input[j];
                store32_le(cipher_text, p ^ load32_le(plain_text));
                cipher_text += 4;
                plain_text  += 4;
            }
        } else {
            FOR (j, 0, 16) {
                u32 p = pool[j] + input[j];
                store32_le(cipher_text, p);
                cipher_text += 4;
            }
        }
        input[12]++;
        if (input[12] == 0) {
            input[13]++;
        }
    }
    text_size &= 63;

    // Last (incomplete) block
    if (text_size > 0) {
        if (plain_text == 0) {
            plain_text = zero;
        }
        chacha20_rounds(pool, input);
        u8 tmp[64];
        FOR (i, 0, 16) {
            store32_le(tmp + i*4, pool[i] + input[i]);
        }
        FOR (i, 0, text_size) {
            cipher_text[i] = tmp[i] ^ plain_text[i];
        }
        WIPE_BUFFER(tmp);
    }
    WIPE_BUFFER(pool);
    return input[12] + ((u64)input[13] << 32) + (text_size > 0);
}

void crypto_hchacha20(u8 out[32], const u8 key[32], const u8 in [16])
{
    u32 block[16];
    chacha20_init_key(block, key);
    // input
    load32_le_buf(block + 12, in, 4);
    chacha20_rounds(block, block);
    // prevent reversal of the rounds by revealing only half of the buffer.
    store32_le_buf(out   , block   , 4); // constant
    store32_le_buf(out+16, block+12, 4); // counter and nonce
    WIPE_BUFFER(block);
}

u64 crypto_chacha20_ctr(u8 *cipher_text, const u8 *plain_text,
                        size_t text_size, const u8 key[32], const u8 nonce[8],
                        u64 ctr)
{
    u32 input[16];
    chacha20_init_key(input, key);
    input[12] = (u32) ctr;
    input[13] = (u32)(ctr >> 32);
    load32_le_buf(input+14, nonce, 2);
    ctr = chacha20_core(input, cipher_text, plain_text, text_size);
    WIPE_BUFFER(input);
    return ctr;
}

u32 crypto_ietf_chacha20_ctr(u8 *cipher_text, const u8 *plain_text,
                             size_t text_size,
                             const u8 key[32], const u8 nonce[12], u32 ctr)
{
    u32 input[16];
    chacha20_init_key(input, key);
    input[12] = (u32) ctr;
    load32_le_buf(input+13, nonce, 3);
    ctr = (u32)chacha20_core(input, cipher_text, plain_text, text_size);
    WIPE_BUFFER(input);
    return ctr;
}

u64 crypto_xchacha20_ctr(u8 *cipher_text, const u8 *plain_text,
                         size_t text_size,
                         const u8 key[32], const u8 nonce[24], u64 ctr)
{
    u8 sub_key[32];
    crypto_hchacha20(sub_key, key, nonce);
    ctr = crypto_chacha20_ctr(cipher_text, plain_text, text_size,
                              sub_key, nonce+16, ctr);
    WIPE_BUFFER(sub_key);
    return ctr;
}

void crypto_chacha20(u8 *cipher_text, const u8 *plain_text, size_t text_size,
                     const u8 key[32], const u8 nonce[8])
{
    crypto_chacha20_ctr(cipher_text, plain_text, text_size, key, nonce, 0);

}
void crypto_ietf_chacha20(u8 *cipher_text, const u8 *plain_text,
                          size_t text_size,
                          const u8 key[32], const u8 nonce[12])
{
    crypto_ietf_chacha20_ctr(cipher_text, plain_text, text_size, key, nonce, 0);
}

void crypto_xchacha20(u8 *cipher_text, const u8 *plain_text, size_t text_size,
                      const u8 key[32], const u8 nonce[24])
{
    crypto_xchacha20_ctr(cipher_text, plain_text, text_size, key, nonce, 0);
}

/////////////////
/// Poly 1305 ///
/////////////////

// h = (h + c) * r
// preconditions:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->c <= 1_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->r <=   0ffffffc_0ffffffc_0ffffffc_0fffffff
// Postcondition:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
static void poly_block(crypto_poly1305_ctx *ctx)
{
    // s = h + c, without carry propagation
    const u64 s0 = ctx->h[0] + (u64)ctx->c[0]; // s0 <= 1_fffffffe
    const u64 s1 = ctx->h[1] + (u64)ctx->c[1]; // s1 <= 1_fffffffe
    const u64 s2 = ctx->h[2] + (u64)ctx->c[2]; // s2 <= 1_fffffffe
    const u64 s3 = ctx->h[3] + (u64)ctx->c[3]; // s3 <= 1_fffffffe
    const u32 s4 = ctx->h[4] +      ctx->c[4]; // s4 <=          5

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
    const u64 x0 = s0*r0+ s1*rr3+ s2*rr2+ s3*rr1+ s4*rr0; // <= 97ffffe007fffff8
    const u64 x1 = s0*r1+ s1*r0 + s2*rr3+ s3*rr2+ s4*rr1; // <= 8fffffe20ffffff6
    const u64 x2 = s0*r2+ s1*r1 + s2*r0 + s3*rr3+ s4*rr2; // <= 87ffffe417fffff4
    const u64 x3 = s0*r3+ s1*r2 + s2*r1 + s3*r0 + s4*rr3; // <= 7fffffe61ffffff2
    const u32 x4 = s4 * (r0 & 3); // ...recover 2 bits    // <=                f

    // partial reduction modulo 2^130 - 5
    const u32 u5 = x4 + (x3 >> 32); // u5 <= 7ffffff5
    const u64 u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
    const u64 u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
    const u64 u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
    const u64 u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
    const u64 u4 = (u3 >> 32)     + (u5 & 3);

    // Update the hash
    ctx->h[0] = (u32)u0; // u0 <= 1_9ffffff0
    ctx->h[1] = (u32)u1; // u1 <= 1_97ffffe0
    ctx->h[2] = (u32)u2; // u2 <= 1_8fffffe2
    ctx->h[3] = (u32)u3; // u3 <= 1_87ffffe4
    ctx->h[4] = (u32)u4; // u4 <=          4
}

// (re-)initialises the input counter and input buffer
static void poly_clear_c(crypto_poly1305_ctx *ctx)
{
    ZERO(ctx->c, 4);
    ctx->c_idx = 0;
}

static void poly_take_input(crypto_poly1305_ctx *ctx, u8 input)
{
    size_t word = ctx->c_idx >> 2;
    size_t byte = ctx->c_idx & 3;
    ctx->c[word] |= (u32)input << (byte * 8);
    ctx->c_idx++;
}

static void poly_update(crypto_poly1305_ctx *ctx,
                        const u8 *message, size_t message_size)
{
    FOR (i, 0, message_size) {
        poly_take_input(ctx, message[i]);
        if (ctx->c_idx == 16) {
            poly_block(ctx);
            poly_clear_c(ctx);
        }
    }
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const u8 key[32])
{
    // Initial hash is zero
    ZERO(ctx->h, 5);
    // add 2^130 to every input block
    ctx->c[4] = 1;
    poly_clear_c(ctx);
    // load r and pad (r has some of its bits cleared)
    load32_le_buf(ctx->r  , key   , 4);
    load32_le_buf(ctx->pad, key+16, 4);
    FOR (i, 0, 1) { ctx->r[i] &= 0x0fffffff; }
    FOR (i, 1, 4) { ctx->r[i] &= 0x0ffffffc; }
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const u8 *message, size_t message_size)
{
    // Align ourselves with block boundaries
    size_t align = MIN(ALIGN(ctx->c_idx, 16), message_size);
    poly_update(ctx, message, align);
    message      += align;
    message_size -= align;

    // Process the message block by block
    size_t nb_blocks = message_size >> 4;
    FOR (i, 0, nb_blocks) {
        load32_le_buf(ctx->c, message, 4);
        poly_block(ctx);
        message += 16;
    }
    if (nb_blocks > 0) {
        poly_clear_c(ctx);
    }
    message_size &= 15;

    // remaining bytes
    poly_update(ctx, message, message_size);
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
    const u64 u0 = (u64)5     + ctx->h[0]; // <= 1_00000004
    const u64 u1 = (u0 >> 32) + ctx->h[1]; // <= 1_00000000
    const u64 u2 = (u1 >> 32) + ctx->h[2]; // <= 1_00000000
    const u64 u3 = (u2 >> 32) + ctx->h[3]; // <= 1_00000000
    const u64 u4 = (u3 >> 32) + ctx->h[4]; // <=          5
    // u4 indicates how many times we should subtract 2^130-5 (0 or 1)

    // h + pad, minus 2^130-5 if u4 exceeds 3
    const u64 uu0 = (u4 >> 2) * 5 + ctx->h[0] + ctx->pad[0]; // <= 2_00000003
    const u64 uu1 = (uu0 >> 32)   + ctx->h[1] + ctx->pad[1]; // <= 2_00000000
    const u64 uu2 = (uu1 >> 32)   + ctx->h[2] + ctx->pad[2]; // <= 2_00000000
    const u64 uu3 = (uu2 >> 32)   + ctx->h[3] + ctx->pad[3]; // <= 2_00000000

    store32_le(mac     , (u32)uu0);
    store32_le(mac +  4, (u32)uu1);
    store32_le(mac +  8, (u32)uu2);
    store32_le(mac + 12, (u32)uu3);

    WIPE_CTX(ctx);
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
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    };

    // init work vector
    u64 v0 = ctx->hash[0];  u64 v8  = iv[0];
    u64 v1 = ctx->hash[1];  u64 v9  = iv[1];
    u64 v2 = ctx->hash[2];  u64 v10 = iv[2];
    u64 v3 = ctx->hash[3];  u64 v11 = iv[3];
    u64 v4 = ctx->hash[4];  u64 v12 = iv[4] ^ ctx->input_offset[0];
    u64 v5 = ctx->hash[5];  u64 v13 = iv[5] ^ ctx->input_offset[1];
    u64 v6 = ctx->hash[6];  u64 v14 = iv[6] ^ (u64)~(is_last_block - 1);
    u64 v7 = ctx->hash[7];  u64 v15 = iv[7];

    // mangle work vector
    u64 *input = ctx->input;
#define BLAKE2_G(v, a, b, c, d, x, y)                  \
    v##a += v##b + x;  v##d = rotr64(v##d ^ v##a, 32); \
    v##c += v##d;      v##b = rotr64(v##b ^ v##c, 24); \
    v##a += v##b + y;  v##d = rotr64(v##d ^ v##a, 16); \
    v##c += v##d;      v##b = rotr64(v##b ^ v##c, 63)
#define BLAKE2_ROUND(i)                                                 \
    BLAKE2_G(v, 0, 4,  8, 12, input[sigma[i][ 0]], input[sigma[i][ 1]]);\
    BLAKE2_G(v, 1, 5,  9, 13, input[sigma[i][ 2]], input[sigma[i][ 3]]);\
    BLAKE2_G(v, 2, 6, 10, 14, input[sigma[i][ 4]], input[sigma[i][ 5]]);\
    BLAKE2_G(v, 3, 7, 11, 15, input[sigma[i][ 6]], input[sigma[i][ 7]]);\
    BLAKE2_G(v, 0, 5, 10, 15, input[sigma[i][ 8]], input[sigma[i][ 9]]);\
    BLAKE2_G(v, 1, 6, 11, 12, input[sigma[i][10]], input[sigma[i][11]]);\
    BLAKE2_G(v, 2, 7,  8, 13, input[sigma[i][12]], input[sigma[i][13]]);\
    BLAKE2_G(v, 3, 4,  9, 14, input[sigma[i][14]], input[sigma[i][15]])

#ifdef BLAKE2_NO_UNROLLING
    FOR (i, 0, 12) {
        BLAKE2_ROUND(i);
    }
#else
    BLAKE2_ROUND(0);  BLAKE2_ROUND(1);  BLAKE2_ROUND(2);  BLAKE2_ROUND(3);
    BLAKE2_ROUND(4);  BLAKE2_ROUND(5);  BLAKE2_ROUND(6);  BLAKE2_ROUND(7);
    BLAKE2_ROUND(8);  BLAKE2_ROUND(9);  BLAKE2_ROUND(0);  BLAKE2_ROUND(1);
#endif

    // update hash
    ctx->hash[0] ^= v0 ^ v8;   ctx->hash[1] ^= v1 ^ v9;
    ctx->hash[2] ^= v2 ^ v10;  ctx->hash[3] ^= v3 ^ v11;
    ctx->hash[4] ^= v4 ^ v12;  ctx->hash[5] ^= v5 ^ v13;
    ctx->hash[6] ^= v6 ^ v14;  ctx->hash[7] ^= v7 ^ v15;
}

static void blake2b_set_input(crypto_blake2b_ctx *ctx, u8 input, size_t index)
{
    if (index == 0) {
        ZERO(ctx->input, 16);
    }
    size_t word = index >> 3;
    size_t byte = index & 7;
    ctx->input[word] |= (u64)input << (byte << 3);

}

static void blake2b_end_block(crypto_blake2b_ctx *ctx)
{
    if (ctx->input_idx == 128) {  // If buffer is full,
        blake2b_incr(ctx);        // update the input offset
        blake2b_compress(ctx, 0); // and compress the (not last) block
        ctx->input_idx = 0;
    }
}

static void blake2b_update(crypto_blake2b_ctx *ctx,
                           const u8 *message, size_t message_size)
{
    FOR (i, 0, message_size) {
        blake2b_end_block(ctx);
        blake2b_set_input(ctx, message[i], ctx->input_idx);
        ctx->input_idx++;
    }
}

void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                                 const u8           *key, size_t key_size)
{
    // initial hash
    COPY(ctx->hash, iv, 8);
    ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

    ctx->input_offset[0] = 0;         // beginning of the input, no offset
    ctx->input_offset[1] = 0;         // beginning of the input, no offset
    ctx->hash_size       = hash_size; // remember the hash size we want
    ctx->input_idx       = 0;

    // if there is a key, the first block is that key (padded with zeroes)
    if (key_size > 0) {
        crypto_blake2b_update(ctx, key ,       key_size);
        crypto_blake2b_update(ctx, zero, 128 - key_size);
    }
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx)
{
    crypto_blake2b_general_init(ctx, 64, 0, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const u8 *message, size_t message_size)
{
    // Align ourselves with block boundaries
    size_t align = MIN(ALIGN(ctx->input_idx, 128), message_size);
    blake2b_update(ctx, message, align);
    message      += align;
    message_size -= align;

    // Process the message block by block
    FOR (i, 0, message_size >> 7) { // number of blocks
        blake2b_end_block(ctx);
        load64_le_buf(ctx->input, message, 16);
        message += 128;
        ctx->input_idx = 128;
    }
    message_size &= 127;

    // remaining bytes
    blake2b_update(ctx, message, message_size);
}

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, u8 *hash)
{
    // Pad the end of the block with zeroes
    FOR (i, ctx->input_idx, 128) {
        blake2b_set_input(ctx, 0, i);
    }
    blake2b_incr(ctx);        // update the input offset
    blake2b_compress(ctx, 1); // compress the last block
    size_t nb_words = ctx->hash_size >> 3;
    store64_le_buf(hash, ctx->hash, nb_words);
    FOR (i, nb_words << 3, ctx->hash_size) {
        hash[i] = (ctx->hash[i >> 3] >> (8 * (i & 7))) & 0xff;
    }
    WIPE_CTX(ctx);
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

static void blake2b_vtable_init(void *ctx)
{
    crypto_blake2b_init(&((crypto_sign_ctx*)ctx)->hash);
}

static void blake2b_vtable_update(void *ctx, const u8 *m, size_t s)
{
    crypto_blake2b_update(&((crypto_sign_ctx*)ctx)->hash, m, s);
}

static void blake2b_vtable_final(void *ctx, u8 *h)
{
    crypto_blake2b_final(&((crypto_sign_ctx*)ctx)->hash, h);
}

const crypto_sign_vtable crypto_blake2b_vtable = {
    crypto_blake2b,
    blake2b_vtable_init,
    blake2b_vtable_update,
    blake2b_vtable_final,
    sizeof(crypto_sign_ctx),
};

////////////////
/// Argon2 i ///
////////////////
// references to R, Z, Q etc. come from the spec

// Argon2 operates on 1024 byte blocks.
typedef struct { u64 a[128]; } block;

static void wipe_block(block *b)
{
    volatile u64* a = b->a;
    ZERO(a, 128);
}

// updates a Blake2 hash with a 32 bit word, little endian.
static void blake_update_32(crypto_blake2b_ctx *ctx, u32 input)
{
    u8 buf[4];
    store32_le(buf, input);
    crypto_blake2b_update(ctx, buf, 4);
    WIPE_BUFFER(buf);
}

static void load_block(block *b, const u8 bytes[1024])
{
    load64_le_buf(b->a, bytes, 128);
}

static void store_block(u8 bytes[1024], const block *b)
{
    store64_le_buf(bytes, b->a, 128);
}

static void copy_block(block *o,const block*in){FOR(i,0,128)o->a[i] = in->a[i];}
static void  xor_block(block *o,const block*in){FOR(i,0,128)o->a[i]^= in->a[i];}

// Hash with a virtually unlimited digest size.
// Doesn't extract more entropy than the base hash function.
// Mainly used for filling a whole kilobyte block with pseudo-random bytes.
// (One could use a stream cipher with a seed hash as the key, but
//  this would introduce another dependency —and point of failure.)
static void extended_hash(u8       *digest, u32 digest_size,
                          const u8 *input , u32 input_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, MIN(digest_size, 64), 0, 0);
    blake_update_32            (&ctx, digest_size);
    crypto_blake2b_update      (&ctx, input, input_size);
    crypto_blake2b_final       (&ctx, digest);

    if (digest_size > 64) {
        // the conversion to u64 avoids integer overflow on
        // ludicrously big hash sizes.
        u32 r   = (u32)(((u64)digest_size + 31) >> 5) - 2;
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
static void g_copy(block *result, const block *x, const block *y, block* tmp)
{
    copy_block(tmp   , x  ); // tmp    = X
    xor_block (tmp   , y  ); // tmp    = X ^ Y = R
    copy_block(result, tmp); // result = R         (only difference with g_xor)
    g_rounds  (tmp);         // tmp    = Z
    xor_block (result, tmp); // result = R ^ Z
}

// The compression function G (xor version for subsequent passes)
static void g_xor(block *result, const block *x, const block *y, block *tmp)
{
    copy_block(tmp   , x  ); // tmp    = X
    xor_block (tmp   , y  ); // tmp    = X ^ Y = R
    xor_block (result, tmp); // result = R ^ old   (only difference with g_copy)
    g_rounds  (tmp);         // tmp    = Z
    xor_block (result, tmp); // result = R ^ old ^ Z
}

// Unary version of the compression function.
// The missing argument is implied zero.
// Does the transformation in place.
static void unary_g(block *work_block, block *tmp)
{
    // work_block == R
    copy_block(tmp, work_block); // tmp        = R
    g_rounds  (work_block);      // work_block = Z
    xor_block (work_block, tmp); // work_block = Z ^ R
}

// Argon2i uses a kind of stream cipher to determine which reference
// block it will take to synthesise the next block.  This context hold
// that stream's state.  (It's very similar to Chacha20.  The block b
// is analogous to Chacha's own pool)
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
    // seed the beginning of the block...
    ctx->b.a[0] = ctx->pass_number;
    ctx->b.a[1] = 0;  // lane number (we have only one)
    ctx->b.a[2] = ctx->slice_number;
    ctx->b.a[3] = ctx->nb_blocks;
    ctx->b.a[4] = ctx->nb_iterations;
    ctx->b.a[5] = 1;  // type: Argon2i
    ctx->b.a[6] = ctx->ctr;
    ZERO(ctx->b.a + 7, 121); // ...then zero the rest out

    // Shuffle the block thus: ctx->b = G((G(ctx->b, zero)), zero)
    // (G "square" function), to get cheap pseudo-random numbers.
    block tmp;
    unary_g(&ctx->b, &tmp);
    unary_g(&ctx->b, &tmp);
    wipe_block(&tmp);
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

    // Offset from the beginning of the segment.  For the first slice
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
    if ((ctx->offset & 127) == 0) {
        ctx->ctr++;
        gidx_refresh(ctx);
    }
    u32 index  = ctx->offset & 127; // save index  for current call
    u32 offset = ctx->offset;       // save offset for current call
    ctx->offset++;                  // update offset for next call

    // Computes the area size.
    // Pass 0 : all already finished segments plus already constructed
    //          blocks in this segment
    // Pass 1+: 3 last segments plus already constructed
    //          blocks in this segment.  THE SPEC SUGGESTS OTHERWISE.
    //          I CONFORM TO THE REFERENCE IMPLEMENTATION.
    int first_pass  = ctx->pass_number == 0;
    u32 slice_size  = ctx->nb_blocks >> 2;
    u32 nb_segments = first_pass ? ctx->slice_number : 3;
    u32 area_size   = nb_segments * slice_size + offset - 1;

    // Computes the starting position of the reference area.
    // CONTRARY TO WHAT THE SPEC SUGGESTS, IT STARTS AT THE
    // NEXT SEGMENT, NOT THE NEXT BLOCK.
    u32 next_slice = ((ctx->slice_number + 1) & 3) * slice_size;
    u32 start_pos  = first_pass ? 0 : next_slice;

    // Generate offset from J1 (no need for J2, there's only one lane)
    u64 j1  = ctx->b.a[index] & 0xffffffff; // pseudo-random number
    u64 x   = (j1 * j1)       >> 32;
    u64 y   = (area_size * x) >> 32;
    u64 z   = (area_size - 1) - y;
    u64 ref = start_pos + z;                // ref < 2 * nb_blocks
    return ref < ctx->nb_blocks ? ref : ref - ctx->nb_blocks;
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
        block tmp_block;
        u8    hash_area[1024];
        store32_le(initial_hash + 64, 0); // first  additional word
        store32_le(initial_hash + 68, 0); // second additional word
        extended_hash(hash_area, 1024, initial_hash, 72);
        load_block(&tmp_block, hash_area);
        copy_block(blocks, &tmp_block);

        store32_le(initial_hash + 64, 1); // slight modification
        extended_hash(hash_area, 1024, initial_hash, 72);
        load_block(&tmp_block, hash_area);
        copy_block(blocks + 1, &tmp_block);

        WIPE_BUFFER(initial_hash);
        WIPE_BUFFER(hash_area);
        wipe_block(&tmp_block);
    }

    // Actual number of blocks
    nb_blocks -= nb_blocks & 3; // round down to 4 p (p == 1 thread)
    const u32 segment_size = nb_blocks >> 2;

    // fill (then re-fill) the rest of the blocks
    block tmp;
    gidx_ctx ctx; // public information, no need to wipe
    FOR_T (u32, pass_number, 0, nb_iterations) {
        int first_pass = pass_number == 0;

        FOR_T (u32, segment, 0, 4) {
            gidx_init(&ctx, pass_number, segment, nb_blocks, nb_iterations);

            // On the first segment of the first pass,
            // blocks 0 and 1 are already filled.
            // We use the offset to skip them.
            u32 start_offset  = first_pass && segment == 0 ? 2 : 0;
            u32 segment_start = segment * segment_size + start_offset;
            u32 segment_end   = (segment + 1) * segment_size;
            FOR_T (u32, current_block, segment_start, segment_end) {
                u32 reference_block = gidx_next(&ctx);
                u32 previous_block  = current_block == 0
                                    ? nb_blocks - 1
                                    : current_block - 1;
                block *c = blocks + current_block;
                block *p = blocks + previous_block;
                block *r = blocks + reference_block;
                if (first_pass) { g_copy(c, p, r, &tmp); }
                else            { g_xor (c, p, r, &tmp); }
            }
        }
    }
    wipe_block(&tmp);
    // hash the very last block with H' into the output hash
    u8 final_block[1024];
    store_block(final_block, blocks + (nb_blocks - 1));
    extended_hash(hash, hash_size, final_block, 1024);
    WIPE_BUFFER(final_block);

    // wipe work area
    volatile u64 *p = (u64*)work_area;
    ZERO(p, 128 * nb_blocks);
}

void crypto_argon2i(u8   *hash,      u32 hash_size,
                    void *work_area, u32 nb_blocks, u32 nb_iterations,
                    const u8 *password,  u32 password_size,
                    const u8 *salt,      u32 salt_size)
{
    crypto_argon2i_general(hash, hash_size, work_area, nb_blocks, nb_iterations,
                           password, password_size, salt , salt_size, 0,0,0,0);
}

////////////////////////////////////
/// Arithmetic modulo 2^255 - 19 ///
////////////////////////////////////
//  Taken from SUPERCOP's ref10 implementation.
//  A bit bigger than TweetNaCl, over 4 times faster.

// field element
typedef i32 fe[10];

static void fe_0(fe h) {           ZERO(h  , 10); }
static void fe_1(fe h) { h[0] = 1; ZERO(h+1,  9); }

static void fe_copy(fe h,const fe f           ){FOR(i,0,10) h[i] =  f[i];      }
static void fe_neg (fe h,const fe f           ){FOR(i,0,10) h[i] = -f[i];      }
static void fe_add (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] + g[i];}
static void fe_sub (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] - g[i];}

static void fe_cswap(fe f, fe g, int b)
{
    i32 mask = -b; // -1 = 0xffffffff
    FOR (i, 0, 10) {
        i32 x = (f[i] ^ g[i]) & mask;
        f[i] = f[i] ^ x;
        g[i] = g[i] ^ x;
    }
}

static void fe_ccopy(fe f, const fe g, int b)
{
    i32 mask = -b; // -1 = 0xffffffff
    FOR (i, 0, 10) {
        i32 x = (f[i] ^ g[i]) & mask;
        f[i] = f[i] ^ x;
    }
}

#define FE_CARRY                                                        \
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;                         \
    c9 = (t9 + ((i64)1<<24)) >> 25; t0 += c9 * 19; t9 -= c9 * ((i64)1 << 25); \
    c1 = (t1 + ((i64)1<<24)) >> 25; t2 += c1;      t1 -= c1 * ((i64)1 << 25); \
    c3 = (t3 + ((i64)1<<24)) >> 25; t4 += c3;      t3 -= c3 * ((i64)1 << 25); \
    c5 = (t5 + ((i64)1<<24)) >> 25; t6 += c5;      t5 -= c5 * ((i64)1 << 25); \
    c7 = (t7 + ((i64)1<<24)) >> 25; t8 += c7;      t7 -= c7 * ((i64)1 << 25); \
    c0 = (t0 + ((i64)1<<25)) >> 26; t1 += c0;      t0 -= c0 * ((i64)1 << 26); \
    c2 = (t2 + ((i64)1<<25)) >> 26; t3 += c2;      t2 -= c2 * ((i64)1 << 26); \
    c4 = (t4 + ((i64)1<<25)) >> 26; t5 += c4;      t4 -= c4 * ((i64)1 << 26); \
    c6 = (t6 + ((i64)1<<25)) >> 26; t7 += c6;      t6 -= c6 * ((i64)1 << 26); \
    c8 = (t8 + ((i64)1<<25)) >> 26; t9 += c8;      t8 -= c8 * ((i64)1 << 26); \
    h[0]=(i32)t0;  h[1]=(i32)t1;  h[2]=(i32)t2;  h[3]=(i32)t3;  h[4]=(i32)t4; \
    h[5]=(i32)t5;  h[6]=(i32)t6;  h[7]=(i32)t7;  h[8]=(i32)t8;  h[9]=(i32)t9

static void fe_frombytes(fe h, const u8 s[32])
{
    i64 t0 =  load32_le(s);
    i64 t1 =  load24_le(s +  4) << 6;
    i64 t2 =  load24_le(s +  7) << 5;
    i64 t3 =  load24_le(s + 10) << 3;
    i64 t4 =  load24_le(s + 13) << 2;
    i64 t5 =  load32_le(s + 16);
    i64 t6 =  load24_le(s + 20) << 7;
    i64 t7 =  load24_le(s + 23) << 5;
    i64 t8 =  load24_le(s + 26) << 4;
    i64 t9 = (load24_le(s + 29) & 0x7fffff) << 2;
    FE_CARRY;
}

// multiply a field element by a signed 32-bit integer
static void fe_mul_small(fe h, const fe f, i32 g)
{
    i64 t0 = f[0] * (i64) g;  i64 t1 = f[1] * (i64) g;
    i64 t2 = f[2] * (i64) g;  i64 t3 = f[3] * (i64) g;
    i64 t4 = f[4] * (i64) g;  i64 t5 = f[5] * (i64) g;
    i64 t6 = f[6] * (i64) g;  i64 t7 = f[7] * (i64) g;
    i64 t8 = f[8] * (i64) g;  i64 t9 = f[9] * (i64) g;
    FE_CARRY;
}
static void fe_mul121666(fe h, const fe f) { fe_mul_small(h, f, 121666); }

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

#define CARRY                                                           \
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;                         \
    c0 = (h0 + ((i64)1<<25)) >> 26; h1 += c0;      h0 -= c0 * ((i64)1 << 26); \
    c4 = (h4 + ((i64)1<<25)) >> 26; h5 += c4;      h4 -= c4 * ((i64)1 << 26); \
    c1 = (h1 + ((i64)1<<24)) >> 25; h2 += c1;      h1 -= c1 * ((i64)1 << 25); \
    c5 = (h5 + ((i64)1<<24)) >> 25; h6 += c5;      h5 -= c5 * ((i64)1 << 25); \
    c2 = (h2 + ((i64)1<<25)) >> 26; h3 += c2;      h2 -= c2 * ((i64)1 << 26); \
    c6 = (h6 + ((i64)1<<25)) >> 26; h7 += c6;      h6 -= c6 * ((i64)1 << 26); \
    c3 = (h3 + ((i64)1<<24)) >> 25; h4 += c3;      h3 -= c3 * ((i64)1 << 25); \
    c7 = (h7 + ((i64)1<<24)) >> 25; h8 += c7;      h7 -= c7 * ((i64)1 << 25); \
    c4 = (h4 + ((i64)1<<25)) >> 26; h5 += c4;      h4 -= c4 * ((i64)1 << 26); \
    c8 = (h8 + ((i64)1<<25)) >> 26; h9 += c8;      h8 -= c8 * ((i64)1 << 26); \
    c9 = (h9 + ((i64)1<<24)) >> 25; h0 += c9 * 19; h9 -= c9 * ((i64)1 << 25); \
    c0 = (h0 + ((i64)1<<25)) >> 26; h1 += c0;      h0 -= c0 * ((i64)1 << 26); \
    h[0]=(i32)h0;  h[1]=(i32)h1;  h[2]=(i32)h2;  h[3]=(i32)h3;  h[4]=(i32)h4; \
    h[5]=(i32)h5;  h[6]=(i32)h6;  h[7]=(i32)h7;  h[8]=(i32)h8;  h[9]=(i32)h9

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

// h = 2 * (f^2)
static void fe_sq2(fe h, const fe f)
{
    fe_sq(h, f);
    fe_mul_small(h, h, 2);
}

// This could be simplified, but it would be slower
static void fe_pow22523(fe out, const fe z)
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
    WIPE_BUFFER(t0);
    WIPE_BUFFER(t1);
    WIPE_BUFFER(t2);
}

// Inverting means multiplying by 2^255 - 21
// 2^255 - 21 = (2^252 - 3) * 8 + 3
// So we reuse the multiplication chain of fe_pow22523
static void fe_invert(fe out, const fe z)
{
    fe tmp;
    fe_pow22523(tmp, z);
    // tmp2^8 * z^3
    fe_sq(tmp, tmp);                        // 0
    fe_sq(tmp, tmp);  fe_mul(tmp, tmp, z);  // 1
    fe_sq(tmp, tmp);  fe_mul(out, tmp, z);  // 1
    WIPE_BUFFER(tmp);
}

static void fe_tobytes(u8 s[32], const fe h)
{
    i32 t[10];
    COPY(t, h, 10);
    i32 q = (19 * t[9] + (((i32) 1) << 24)) >> 25;
    FOR (i, 0, 5) {
        q += t[2*i  ]; q >>= 26;
        q += t[2*i+1]; q >>= 25;
    }
    t[0] += 19 * q;
    q = 0;
    FOR (i, 0, 5) {
        t[i*2  ] += q;  q = t[i*2  ] >> 26;  t[i*2  ] -= q * ((i32)1 << 26);
        t[i*2+1] += q;  q = t[i*2+1] >> 25;  t[i*2+1] -= q * ((i32)1 << 25);
    }

    store32_le(s +  0, ((u32)t[0] >>  0) | ((u32)t[1] << 26));
    store32_le(s +  4, ((u32)t[1] >>  6) | ((u32)t[2] << 19));
    store32_le(s +  8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
    store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] <<  6));
    store32_le(s + 16, ((u32)t[5] >>  0) | ((u32)t[6] << 25));
    store32_le(s + 20, ((u32)t[6] >>  7) | ((u32)t[7] << 19));
    store32_le(s + 24, ((u32)t[7] >> 13) | ((u32)t[8] << 12));
    store32_le(s + 28, ((u32)t[8] >> 20) | ((u32)t[9] <<  6));

    WIPE_BUFFER(t);
}

//  Parity check.  Returns 0 if even, 1 if odd
static int fe_isodd(const fe f)
{
    u8 s[32];
    fe_tobytes(s, f);
    u8 isodd = s[0] & 1;
    WIPE_BUFFER(s);
    return isodd;
}

// Returns 0 if zero, 1 if non zero
static int fe_isnonzero(const fe f)
{
    u8 s[32];
    fe_tobytes(s, f);
    int isnonzero = zerocmp32(s);
    WIPE_BUFFER(s);
    return -isnonzero;
}

// Returns 1 if equal, 0 if not equal
static int fe_isequal(const fe f, const fe g)
{
    fe diff;
    fe_sub(diff, f, g);
    int isdifferent = fe_isnonzero(diff);
    WIPE_BUFFER(diff);
    return 1 - isdifferent;
}

static const fe sqrtm1 = { -32595792, -7943725, 9377950, 3500415, 12389472,
                           -272473, -25146209, -2005654, 326686, 11406482,};

// Inverse square root.
// Returns true if x is a non zero square, false otherwise.
// After the call:
//   isr = sqrt(1/x)        if x is non-zero square.
//   isr = sqrt(sqrt(-1)/x) if x is not a square.
//   isr = 0                if x is zero.
// We do not guarantee the sign of the square root.
//
// Notes:
// Let quartic = x^((p-1)/4)
//
// x^((p-1)/2) = chi(x)
// quartic^2   = chi(x)
// quartic     = sqrt(chi(x))
// quartic     = 1 or -1 or sqrt(-1) or -sqrt(-1)
//
// Note that x is a square if quartic is 1 or -1
// There are 4 cases to consider:
//
// if   quartic         = 1  (x is a square)
// then x^((p-1)/4)     = 1
//      x^((p-5)/4) * x = 1
//      x^((p-5)/4)     = 1/x
//      x^((p-5)/8)     = sqrt(1/x) or -sqrt(1/x)
//
// if   quartic                = -1  (x is a square)
// then x^((p-1)/4)            = -1
//      x^((p-5)/4) * x        = -1
//      x^((p-5)/4)            = -1/x
//      x^((p-5)/8)            = sqrt(-1)   / sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = sqrt(-1)^2 / sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = -1/sqrt(x)
//      x^((p-5)/8) * sqrt(-1) = -sqrt(1/x) or sqrt(1/x)
//
// if   quartic         = sqrt(-1)  (x is not a square)
// then x^((p-1)/4)     = sqrt(-1)
//      x^((p-5)/4) * x = sqrt(-1)
//      x^((p-5)/4)     = sqrt(-1)/x
//      x^((p-5)/8)     = sqrt(sqrt(-1)/x) or -sqrt(sqrt(-1)/x)
//
// Note that the product of two non-squares is always a square:
//   For any non-squares a and b, chi(a) = -1 and chi(b) = -1.
//   Since chi(x) = x^((p-1)/2), chi(a)*chi(b) = chi(a*b) = 1.
//   Therefore a*b is a square.
//
//   Since sqrt(-1) and x are both non-squares, their product is a
//   square, and we can compute their square root.
//
// if   quartic                = -sqrt(-1)  (x is not a square)
// then x^((p-1)/4)            = -sqrt(-1)
//      x^((p-5)/4) * x        = -sqrt(-1)
//      x^((p-5)/4)            = -sqrt(-1)/x
//      x^((p-5)/8)            = sqrt(-sqrt(-1)/x)
//      x^((p-5)/8)            = sqrt( sqrt(-1)/x) * sqrt(-1)
//      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * sqrt(-1)^2
//      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * -1
//      x^((p-5)/8) * sqrt(-1) = -sqrt(sqrt(-1)/x) or sqrt(sqrt(-1)/x)
static int invsqrt(fe isr, const fe x)
{
    fe check, quartic;
    fe_copy(check, x);
    fe_pow22523(isr, check);
    fe_sq (quartic, isr);
    fe_mul(quartic, quartic, check);
    fe_1  (check);          int p1 = fe_isequal(quartic, check);
    fe_neg(check, check );  int m1 = fe_isequal(quartic, check);
    fe_neg(check, sqrtm1);  int ms = fe_isequal(quartic, check);
    fe_mul(check, isr, sqrtm1);
    fe_ccopy(isr, check, m1 | ms);
    WIPE_BUFFER(quartic);
    WIPE_BUFFER(check);
    return p1 | m1;
}

// trim a scalar for scalar multiplication
static void trim_scalar(u8 trimmed[32], const u8 scalar[32])
{
    COPY(trimmed, scalar, 32);
    trimmed[ 0] &= 248;
    trimmed[31] &= 127;
    trimmed[31] |= 64;
}

// get bit from scalar at position i
static int scalar_bit(const u8 s[32], int i)
{
    if (i < 0) { return 0; } // handle -1 for sliding windows
    return (s[i>>3] >> (i&7)) & 1;
}

///////////////
/// X-25519 /// Taken from SUPERCOP's ref10 implementation.
///////////////
static void scalarmult(u8 q[32], const u8 scalar[32], const u8 p[32],
                       size_t nb_bits)
{
    // computes the scalar product
    fe x1;
    fe_frombytes(x1, p);

    // computes the actual scalar product (the result is in x2 and z2)
    fe x2, z2, x3, z3, t0, t1;
    // Montgomery ladder
    // In projective coordinates, to avoid divisions: x = X / Z
    // We don't care about the y coordinate, it's only 1 bit of information
    fe_1(x2);        fe_0(z2); // "zero" point
    fe_copy(x3, x1); fe_1(z3); // "one"  point
    int swap = 0;
    for (int pos = nb_bits-1; pos >= 0; --pos) {
        // constant time conditional swap before ladder step
        int b = scalar_bit(scalar, pos);
        swap ^= b; // xor trick avoids swapping at the end of the loop
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;  // anticipates one last swap after the loop

        // Montgomery ladder step: replaces (P2, P3) by (P2*2, P2+P3)
        // with differential addition
        fe_sub(t0, x3, z3);
        fe_sub(t1, x2, z2);
        fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);
        fe_mul(z3, t0, x2);
        fe_mul(z2, z2, t1);
        fe_sq (t0, t1    );
        fe_sq (t1, x2    );
        fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);
        fe_mul(x2, t1, t0);
        fe_sub(t1, t1, t0);
        fe_sq (z2, z2    );
        fe_mul121666(z3, t1);
        fe_sq (x3, x3    );
        fe_add(t0, t0, z3);
        fe_mul(z3, x1, z2);
        fe_mul(z2, t1, t0);
    }
    // last swap is necessary to compensate for the xor trick
    // Note: after this swap, P3 == P2 + P1.
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    // normalises the coordinates: x == X / Z
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(q, x2);

    WIPE_BUFFER(x1);
    WIPE_BUFFER(x2);  WIPE_BUFFER(z2);  WIPE_BUFFER(t0);
    WIPE_BUFFER(x3);  WIPE_BUFFER(z3);  WIPE_BUFFER(t1);
}

void crypto_x25519(u8       raw_shared_secret[32],
                   const u8 your_secret_key  [32],
                   const u8 their_public_key [32])
{
    // restrict the possible scalar values
    u8 e[32];
    trim_scalar(e, your_secret_key);
    scalarmult(raw_shared_secret, e, their_public_key, 255);
    WIPE_BUFFER(e);
}

void crypto_x25519_public_key(u8       public_key[32],
                              const u8 secret_key[32])
{
    static const u8 base_point[32] = {9};
    crypto_x25519(public_key, secret_key, base_point);
}

///////////////////////////
/// Arithmetic modulo L ///
///////////////////////////
static const  u8 L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
    0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, };

// r = x mod L (little-endian)
static void modL(u8 *r, i64 x[64])
{
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
    FOR (i, 0, 32) {
        x[i] += carry - (x[31] >> 4) * L[i];
        carry = x[i] >> 8;
        x[i] &= 255;
    }
    FOR (i, 0, 32) {
        x[i] -= carry * L[i];
    }
    FOR (i, 0, 32) {
        x[i+1] += x[i] >> 8;
        r[i  ]  = x[i] & 255;
    }
}

// Reduces a 64-byte hash modulo L (little endian)
static void reduce(u8 r[64])
{
    i64 x[64];
    COPY(x, r, 64);
    modL(r, x);
    WIPE_BUFFER(x);
}

// r = (a * b) + c
static void mul_add(u8 r[32], const u8 a[32], const u8 b[32], const u8 c[32])
{
    i64 s[64];
    FOR (i, 0, 32) {
        s[i] = (i64)(u64)c[i];  // preserve unsigned
    }
    ZERO(s + 32, 32);
    FOR (i,  0, 32) {
        FOR (j, 0, 32) {
            s[i+j] += a[i] * (u64)b[j];
        }
    }
    modL(r, s);
    WIPE_BUFFER(s);
}

// Variable time! a must not be secret!
static int is_above_L(const u8 a[32])
{
    for (int i = 31; i >= 0; i--) {
        if (a[i] > L[i]) { return 1; }
        if (a[i] < L[i]) { return 0; }
    }
    return 1;
}

///////////////
/// Ed25519 ///
///////////////

// Point (group element, ge) in a twisted Edwards curve,
// in extended projective coordinates.
// ge        : x  = X/Z, y  = Y/Z, T  = XY/Z
// ge_cached : Yp = X+Y, Ym = X-Y, T2 = T*D2
// ge_precomp: Z  = 1
typedef struct { fe X;  fe Y;  fe Z; fe T;  } ge;
typedef struct { fe Yp; fe Ym; fe Z; fe T2; } ge_cached;
typedef struct { fe Yp; fe Ym;       fe T2; } ge_precomp;

static void ge_zero(ge *p)
{
    fe_0(p->X);
    fe_1(p->Y);
    fe_1(p->Z);
    fe_0(p->T);
}

static void ge_tobytes(u8 s[32], const ge *h)
{
    fe recip, x, y;
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isodd(x) << 7;

    WIPE_BUFFER(recip);
    WIPE_BUFFER(x);
    WIPE_BUFFER(y);
}

// h = s, where s is a point encoded in 32 bytes
//
// Variable time!  Inputs must not be secret!
// => Use only to *check* signatures.
//
// From the specifications:
//   The encoding of s contains y and the sign of x
//   x = sqrt((y^2 - 1) / (d*y^2 + 1))
// In extended coordinates:
//   X = x, Y = y, Z = 1, T = x*y
//
//    Note that num * den is a square iff num / den is a square
//    If num * den is not a square, the point was not on the curve.
// From the above:
//   Let num =   y^2 - 1
//   Let den = d*y^2 + 1
//   x = sqrt((y^2 - 1) / (d*y^2 + 1))
//   x = sqrt(num / den)
//   x = sqrt(num^2 / (num * den))
//   x = num * sqrt(1 / (num * den))
//
// Therefore, we can just compute:
//   num =   y^2 - 1
//   den = d*y^2 + 1
//   isr = invsqrt(num * den)  // abort if not square
//   x   = num * isr
// Finally, negate x if its sign is not as specified.
static int ge_frombytes_vartime(ge *h, const u8 s[32])
{
    static const fe d = { // −121665 / 121666
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116
    };
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq (h->T, h->Y);        // t =   y^2
    fe_mul(h->X, h->T, d   );  // x = d*y^2
    fe_sub(h->T, h->T, h->Z);  // t =   y^2 - 1
    fe_add(h->X, h->X, h->Z);  // x = d*y^2 + 1
    fe_mul(h->X, h->T, h->X);  // x = (y^2 - 1) * (d*y^2 + 1)
    int is_square = invsqrt(h->X, h->X);
    if (!is_square) {
        return -1;             // Not on the curve, abort
    }
    fe_mul(h->X, h->T, h->X);  // x = sqrt((y^2 - 1) / (d*y^2 + 1))
    if (fe_isodd(h->X) != (s[31] >> 7)) {
        fe_neg(h->X, h->X);
    }
    fe_mul(h->T, h->X, h->Y);
    return 0;
}

// - 2 * 121665 / 121666
static const fe D2 = {-21827239, -5839606, -30745221, 13898782, 229458,
                      15978800, -12551817, -6495438, 29715968, 9444199,};

static void ge_cache(ge_cached *c, const ge *p)
{
    fe_add (c->Yp, p->Y, p->X);
    fe_sub (c->Ym, p->Y, p->X);
    fe_copy(c->Z , p->Z      );
    fe_mul (c->T2, p->T, D2  );
}

// Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static void ge_add(ge *s, const ge *p, const ge_cached *q)
{
    fe a, b;
    fe_add(a   , p->Y, p->X );
    fe_sub(b   , p->Y, p->X );
    fe_mul(a   , a   , q->Yp);
    fe_mul(b   , b   , q->Ym);
    fe_add(s->Y, a   , b    );
    fe_sub(s->X, a   , b    );

    fe_add(s->Z, p->Z, p->Z );
    fe_mul(s->Z, s->Z, q->Z );
    fe_mul(s->T, p->T, q->T2);
    fe_add(a   , s->Z, s->T );
    fe_sub(b   , s->Z, s->T );

    fe_mul(s->T, s->X, s->Y);
    fe_mul(s->X, s->X, b   );
    fe_mul(s->Y, s->Y, a   );
    fe_mul(s->Z, a   , b   );
}

// Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static void ge_sub(ge *s, const ge *p, const ge_cached *q)
{
    ge_cached neg;
    fe_copy(neg.Ym, q->Yp);
    fe_copy(neg.Yp, q->Ym);
    fe_copy(neg.Z , q->Z );
    fe_neg (neg.T2, q->T2);
    ge_add(s, p, &neg);
}

static void ge_madd(ge *s, const ge *p, const ge_precomp *q, fe a, fe b)
{
    fe_add(a   , p->Y, p->X );
    fe_sub(b   , p->Y, p->X );
    fe_mul(a   , a   , q->Yp);
    fe_mul(b   , b   , q->Ym);
    fe_add(s->Y, a   , b    );
    fe_sub(s->X, a   , b    );

    fe_add(s->Z, p->Z, p->Z );
    fe_mul(s->T, p->T, q->T2);
    fe_add(a   , s->Z, s->T );
    fe_sub(b   , s->Z, s->T );

    fe_mul(s->T, s->X, s->Y);
    fe_mul(s->X, s->X, b   );
    fe_mul(s->Y, s->Y, a   );
    fe_mul(s->Z, a   , b   );
}

static void ge_msub(ge *s, const ge *p, const ge_precomp *q, fe a, fe b)
{
    fe_add(a   , p->Y, p->X );
    fe_sub(b   , p->Y, p->X );
    fe_mul(a   , a   , q->Ym);
    fe_mul(b   , b   , q->Yp);
    fe_add(s->Y, a   , b    );
    fe_sub(s->X, a   , b    );

    fe_add(s->Z, p->Z, p->Z );
    fe_mul(s->T, p->T, q->T2);
    fe_sub(a   , s->Z, s->T );
    fe_add(b   , s->Z, s->T );

    fe_mul(s->T, s->X, s->Y);
    fe_mul(s->X, s->X, b   );
    fe_mul(s->Y, s->Y, a   );
    fe_mul(s->Z, a   , b   );
}

static void ge_double(ge *s, const ge *p, ge *q)
{
    fe_sq (q->X, p->X);
    fe_sq (q->Y, p->Y);
    fe_sq2(q->Z, p->Z);
    fe_add(q->T, p->X, p->Y);
    fe_sq (s->T, q->T);
    fe_add(q->T, q->Y, q->X);
    fe_sub(q->Y, q->Y, q->X);
    fe_sub(q->X, s->T, q->T);
    fe_sub(q->Z, q->Z, q->Y);

    fe_mul(s->X, q->X , q->Z);
    fe_mul(s->Y, q->T , q->Y);
    fe_mul(s->Z, q->Y , q->Z);
    fe_mul(s->T, q->X , q->T);
}

// 5-bit signed window in cached format (Niels coordinates, Z=1)
static const ge_precomp b_window[8] = {
    {{25967493,-14356035,29566456,3660896,-12694345,
      4014787,27544626,-11754271,-6079156,2047605,},
     {-12545711,934262,-2722910,3049990,-727428,
      9406986,12720692,5043384,19500929,-15469378,},
     {-8738181,4489570,9688441,-14785194,10184609,
      -12363380,29287919,11864899,-24514362,-4438546,},},
    {{15636291,-9688557,24204773,-7912398,616977,
      -16685262,27787600,-14772189,28944400,-1550024,},
     {16568933,4717097,-11556148,-1102322,15682896,
      -11807043,16354577,-11775962,7689662,11199574,},
     {30464156,-5976125,-11779434,-15670865,23220365,
      15915852,7512774,10017326,-17749093,-9920357,},},
    {{10861363,11473154,27284546,1981175,-30064349,
      12577861,32867885,14515107,-15438304,10819380,},
     {4708026,6336745,20377586,9066809,-11272109,
      6594696,-25653668,12483688,-12668491,5581306,},
     {19563160,16186464,-29386857,4097519,10237984,
      -4348115,28542350,13850243,-23678021,-15815942,},},
    {{5153746,9909285,1723747,-2777874,30523605,
      5516873,19480852,5230134,-23952439,-15175766,},
     {-30269007,-3463509,7665486,10083793,28475525,
      1649722,20654025,16520125,30598449,7715701,},
     {28881845,14381568,9657904,3680757,-20181635,
      7843316,-31400660,1370708,29794553,-1409300,},},
    {{-22518993,-6692182,14201702,-8745502,-23510406,
      8844726,18474211,-1361450,-13062696,13821877,},
     {-6455177,-7839871,3374702,-4740862,-27098617,
      -10571707,31655028,-7212327,18853322,-14220951,},
     {4566830,-12963868,-28974889,-12240689,-7602672,
      -2830569,-8514358,-10431137,2207753,-3209784,},},
    {{-25154831,-4185821,29681144,7868801,-6854661,
      -9423865,-12437364,-663000,-31111463,-16132436,},
     {25576264,-2703214,7349804,-11814844,16472782,
      9300885,3844789,15725684,171356,6466918,},
     {23103977,13316479,9739013,-16149481,817875,
      -15038942,8965339,-14088058,-30714912,16193877,},},
    {{-33521811,3180713,-2394130,14003687,-16903474,
      -16270840,17238398,4729455,-18074513,9256800,},
     {-25182317,-4174131,32336398,5036987,-21236817,
      11360617,22616405,9761698,-19827198,630305,},
     {-13720693,2639453,-24237460,-7406481,9494427,
      -5774029,-6554551,-15960994,-2449256,-14291300,},},
    {{-3151181,-5046075,9282714,6866145,-31907062,
      -863023,-18940575,15033784,25105118,-7894876,},
     {-24326370,15950226,-31801215,-14592823,-11662737,
      -5090925,1573892,-2625887,2198790,-15804619,},
     {-3099351,10324967,-2241613,7453183,-5446979,
      -2735503,-13812022,-16236442,-32461234,-12290683,},},
};

// Incremental sliding windows (left to right)
// Based on Roberto Maria Avanzi[2005]
typedef struct {
    i16 next_index; // position of the next signed digit
    i8  next_digit; // next signed digit (odd number below 2^window_width)
    u8  next_check; // point at which we must check for a new window
} slide_ctx;

static void slide_init(slide_ctx *ctx, const u8 scalar[32])
{
    // scalar is guaranteed to be below L, either because we checked (s),
    // or because we reduced it modulo L (h_ram). L is under 2^253, so
    // so bits 253 to 255 are guaranteed to be zero. No need to test them.
    //
    // Note however that L is very close to 2^252, so bit 252 is almost
    // always zero.  If we were to start at bit 251, the tests wouldn't
    // catch the off-by-one error (constructing one that does would be
    // prohibitively expensive).
    //
    // We should still check bit 252, though.
    int i = 252;
    while (i > 0 && scalar_bit(scalar, i) == 0) {
        i--;
    }
    ctx->next_check = (u8)(i + 1);
    ctx->next_index = -1;
    ctx->next_digit = -1;
}

static int slide_step(slide_ctx *ctx, int width, int i, const u8 scalar[32])
{
    if (i == ctx->next_check) {
        if (scalar_bit(scalar, i) == scalar_bit(scalar, i - 1)) {
            ctx->next_check--;
        } else {
            // compute digit of next window
            int w = MIN(width, i + 1);
            int v = -(scalar_bit(scalar, i) << (w-1));
            FOR_T (int, j, 0, w-1) {
                v += scalar_bit(scalar, i-(w-1)+j) << j;
            }
            v += scalar_bit(scalar, i-w);
            int lsb = v & (~v + 1);            // smallest bit of v
            int s   = (   ((lsb & 0xAA) != 0)  // log2(lsb)
                       | (((lsb & 0xCC) != 0) << 1)
                       | (((lsb & 0xF0) != 0) << 2));
            ctx->next_index  = (i16)(i-(w-1)+s);
            ctx->next_digit  = (i8) (v >> s   );
            ctx->next_check -= w;
        }
    }
    return i == ctx->next_index ? ctx->next_digit: 0;
}

#define P_W_WIDTH 3 // Affects the size of the stack
#define B_W_WIDTH 5 // Affects the size of the binary
#define P_W_SIZE  (1<<(P_W_WIDTH-2))

// P = [b]B + [p]P, where B is the base point
//
// Variable time! Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static void ge_double_scalarmult_vartime(ge *P, const u8 p[32], const u8 b[32])
{
    // cache P window for addition
    ge_cached cP[P_W_SIZE];
    {
        ge P2, tmp;
        ge_double(&P2, P, &tmp);
        ge_cache(&cP[0], P);
        FOR (i, 1, P_W_SIZE) {
            ge_add(&tmp, &P2, &cP[i-1]);
            ge_cache(&cP[i], &tmp);
        }
    }

    // Merged double and add ladder, fused with sliding
    slide_ctx p_slide;  slide_init(&p_slide, p);
    slide_ctx b_slide;  slide_init(&b_slide, b);
    int i = MAX(p_slide.next_check, b_slide.next_check);
    ge *sum = P;
    ge_zero(sum);
    while (i >= 0) {
        ge tmp;
        ge_double(sum, sum, &tmp);
        int p_digit = slide_step(&p_slide, P_W_WIDTH, i, p);
        int b_digit = slide_step(&b_slide, B_W_WIDTH, i, b);
        if (p_digit > 0) { ge_add(sum, sum, &cP[ p_digit / 2]); }
        if (p_digit < 0) { ge_sub(sum, sum, &cP[-p_digit / 2]); }
        fe t1, t2;
        if (b_digit > 0) { ge_madd(sum, sum, b_window +  b_digit/2, t1, t2); }
        if (b_digit < 0) { ge_msub(sum, sum, b_window + -b_digit/2, t1, t2); }
        i--;
    }
}

// R_check = s[B] - h_ram[pk], where B is the base point
//
// Variable time! Internal buffers are not wiped! Inputs must not be secret!
// => Use only to *check* signatures.
static int ge_r_check(u8 R_check[32], u8 s[32], u8 h_ram[32], u8 pk[32])
{
    ge A; // not secret, not wiped
    if (ge_frombytes_vartime(&A, pk) ||         // A = pk
        is_above_L(s)) {                        // prevent s malleability
        return -1;
    }
    fe_neg(A.X, A.X);
    fe_neg(A.T, A.T);                           // A = -pk
    ge_double_scalarmult_vartime(&A, h_ram, s); // A = [s]B - [h_ram]pk
    ge_tobytes(R_check, &A);                    // R_check = A
    return 0;
}

// 5-bit signed comb in cached format (Niels coordinates, Z=1)
static const ge_precomp b_comb[16] = {
    {{2615675,9989699,17617367,-13953520,-8802803,
      1447286,-8909978,-270892,-12199203,-11617247,},
     {8873912,14981221,13714139,6923085,25481101,
      4243739,4646647,-203847,9015725,-16205935,},
     {-18494317,2686822,18449263,-13905325,5966562,
      -3368714,2738304,-8583315,15987143,12180258,},},
    {{-1271192,4785266,-29856067,-6036322,-10435381,
      15493337,20321440,-6036064,15902131,13420909,},
     {-1827892,15407265,2351140,-11810728,28403158,
      -1487103,-15057287,-4656433,-3780118,-1145998,},
     {-33336513,-13705917,-18473364,-5039204,-4268481,
      -4136039,-8192211,-2935105,-19354402,5995895,},},
    {{-26170888,-12891603,9568996,-6197816,26424622,
      16308973,-4518568,-3771275,-15522557,3991142,},
     {-30623162,-11845055,-11327147,-16008347,17564978,
      -1449578,-20580262,14113978,29643661,15580734,},
     {-19753139,-1729018,21880604,13471713,28315373,
      -8530159,-17492688,11730577,-8790216,3942124,},},
    {{-25875044,1958396,19442242,-9809943,-26099408,
      -18589,-30794750,-14100910,4971028,-10535388,},
     {-15109423,13348938,-14756006,14132355,30481360,
      1830723,-240510,9371801,-13907882,8024264,},
     {17278020,3905045,29577748,11151940,18451761,
      -6801382,31480073,-13819665,26308905,10868496,},},
    {{-13896937,-7357727,-12131124,617289,-33188817,
      10080542,6402555,10779157,1176712,2472642,},
     {25119567,5628696,10185251,-9279452,683770,
      -14523112,-7982879,-16450545,1431333,-13253541,},
     {26937294,3313561,28601532,-3497112,-22814130,
      11073654,8956359,-16757370,13465868,16623983,},},
    {{71503,12662254,-17008072,-8370006,23408384,
      -12897959,32287612,11241906,-16724175,15336924,},
     {-8390493,1276691,19008763,-12736675,-9249429,
      -12526388,17434195,-13761261,18962694,-1227728,},
     {-5468054,6059101,-31275300,2469124,26532937,
      8152142,6423741,-11427054,-15537747,-10938247,},},
    {{27397666,4059848,23573959,8868915,-10602416,
      -10456346,-22812831,-9666299,31810345,-2695469,},
     {26361856,-12366343,8941415,15163068,7069802,
      -7240693,-18656349,8167008,31106064,-1670658,},
     {-11303505,-9659620,-12354748,-9331434,19501116,
      -9146390,-841918,-5315657,8903828,8839982,},},
    {{-3418193,-694531,2320482,-11850408,-1981947,
      -9606132,23743894,3933038,-25004889,-4478918,},
     {-5677136,-11012483,-1246680,-6422709,14772010,
      1829629,-11724154,-15914279,-18177362,1301444,},
     {16603354,-215859,1591180,3775832,-705596,
      -13913449,26574704,14963118,19649719,6562441,},},
    {{-4448372,5537982,-4805580,14016777,15544316,
      16039459,-7143453,-8003716,-21904564,8443777,},
     {937094,12383516,-22597284,7580462,-18767748,
      13813292,-2323566,13503298,11510849,-10561992,},
     {33188866,-12232360,-24929148,-6133828,21818432,
      11040754,-3041582,-3524558,-29364727,-10264096,},},
    {{32495180,15749868,2195406,-15542321,-3213890,
      -4030779,-2915317,12751449,-1872493,11926798,},
     {28028043,14715827,-6558532,-1773240,27563607,
      -9374554,3201863,8865591,-16953001,7659464,},
     {-20704194,-12560423,-1235774,-785473,13240395,
      4831780,-472624,-3796899,25480903,-15422283,},},
    {{26779741,12553580,-24344000,-4071926,-19447556,
      -13464636,21989468,7826656,-17344881,10055954,},
     {13628467,5701368,4674031,11935670,11461401,
      10699118,31846435,-114971,-8269924,-14777505,},
     {-2204347,-16313180,-21388048,7520851,-8697745,
      -14460961,20894017,12210317,-475249,-2319102,},},
    {{5848288,-1639207,-10452929,-11760637,6484174,
      -5895268,-11561603,587105,-19220796,14378222,},
     {-22124018,-12859127,11966893,1617732,30972446,
      -14350095,-21822286,8369862,-29443219,-15378798,},
     {-16407882,4940236,-21194947,10781753,22248400,
      14425368,14866511,-7552907,12148703,-7885797,},},
    {{32050187,12536702,9206308,-10016828,-13333241,
      -4276403,-24225594,14562479,-31803624,-9967812,},
     {290131,-471434,8840522,-2654851,25963762,
      -11578288,-7227978,13847103,30641797,6003514,},
     {16376744,15908865,-30663553,4663134,-30882819,
      -10105163,19294784,-10800440,-33259252,2563437,},},
    {{23536033,-6219361,199701,4574817,30045793,
      7163081,-2244033,883497,10960746,-14779481,},
     {-23547482,-11475166,-11913550,9374455,22813401,
      -5707910,26635288,9199956,20574690,2061147,},
     {30208741,11594088,-15145888,15073872,5279309,
      -9651774,8273234,4796404,-31270809,-13316433,},},
    {{-8143354,-11558749,15772067,14293390,5914956,
      -16702904,-7410985,7536196,6155087,16571424,},
     {9715324,7036821,-17981446,-11505533,26555178,
      -3571571,5697062,-14128022,2795223,9694380,},
     {-17802574,14455251,27149077,-7832700,-29163160,
      -7246767,17498491,-4216079,31788733,-14027536,},},
    {{6211591,-11166015,24568352,2768318,-10822221,
      11922793,33211827,3852290,-13160369,-8855385,},
     {14864569,-6319076,-3080,-8151104,4994948,
      -1572144,-41927,9269803,13881712,-13439497,},
     {-25233439,-9389070,-6618212,-3268087,-521386,
      -7350198,21035059,-14970947,25910190,11122681,},},
};


// p = [scalar]B, where B is the base point
static void ge_scalarmult_base(ge *p, const u8 scalar[32])
{
    // 5-bits signed comb, from Mike Hamburg's
    // Fast and compact elliptic-curve cryptography (2012)
    // 1 / 2 modulo L
    static const u8 half_mod_L[32] = {
        0xf7, 0xe9, 0x7a, 0x2e, 0x8d, 0x31, 0x09, 0x2c, 0x6b, 0xce, 0x7b, 0x51,
        0xef, 0x7c, 0x6f, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, };
    // (2^255 - 1) / 2 modulo L
    static const u8 half_ones[32] = {
        0x42, 0x9a, 0xa3, 0xba, 0x23, 0xa5, 0xbf, 0xcb, 0x11, 0x5b, 0x9d, 0xc5,
        0x74, 0x95, 0xf3, 0xb6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, };
    // All bits set form: 1 means 1, 0 means -1
    u8 s_scalar[32];
    mul_add(s_scalar, scalar, half_mod_L, half_ones);

    // Double and add ladder
    fe a, n2; // temporaries for addition
    ge dbl;   // temporary for doubling
    ge_precomp comb;
    ge_zero(p);
    for (int i = 50; i >= 0; i--) {
        if (i < 50) {
            ge_double(p, p, &dbl);
        }
        fe_1(comb.Yp);
        fe_1(comb.Ym);
        fe_0(comb.T2);
        u8 teeth = (u8)((scalar_bit(s_scalar, i)           ) +
                        (scalar_bit(s_scalar, i +  51) << 1) +
                        (scalar_bit(s_scalar, i + 102) << 2) +
                        (scalar_bit(s_scalar, i + 153) << 3) +
                        (scalar_bit(s_scalar, i + 204) << 4));
        u8 high  = teeth >> 4;
        u8 index = (teeth ^ (high - 1)) & 15;
        FOR (j, 0, 16) {
            i32 select = 1 & (((j ^ index) - 1) >> 8);
            fe_ccopy(comb.Yp, b_comb[j].Yp, select);
            fe_ccopy(comb.Ym, b_comb[j].Ym, select);
            fe_ccopy(comb.T2, b_comb[j].T2, select);
        }
        fe_neg(n2, comb.T2);
        fe_cswap(comb.T2, n2     , high);
        fe_cswap(comb.Yp, comb.Ym, high);
        ge_msub(p, p, &comb, a, n2); // reuse n2 as temporary
    }
    WIPE_CTX(&dbl); WIPE_CTX(&comb);
    WIPE_BUFFER(a); WIPE_BUFFER(n2);
    WIPE_BUFFER(s_scalar);
}

void crypto_sign_public_key_custom_hash(u8       public_key[32],
                                        const u8 secret_key[32],
                                        const crypto_sign_vtable *hash)
{
    u8 a[64];
    hash->hash(a, secret_key, 32);
    trim_scalar(a, a);
    ge A;
    ge_scalarmult_base(&A, a);
    ge_tobytes(public_key, &A);
    WIPE_BUFFER(a);
    WIPE_CTX(&A);
}

void crypto_sign_public_key(u8 public_key[32], const u8 secret_key[32])
{
    crypto_sign_public_key_custom_hash(public_key, secret_key,
                                       &crypto_blake2b_vtable);
}

void crypto_sign_init_first_pass_custom_hash(crypto_sign_ctx_abstract *ctx,
                                             const u8 secret_key[32],
                                             const u8 public_key[32],
                                             const crypto_sign_vtable *hash)
{
    ctx->hash  = hash; // set vtable
    u8 *a      = ctx->buf;
    u8 *prefix = ctx->buf + 32;
    ctx->hash->hash(a, secret_key, 32);
    trim_scalar(a, a);

    if (public_key == 0) {
        crypto_sign_public_key_custom_hash(ctx->pk, secret_key, ctx->hash);
    } else {
        COPY(ctx->pk, public_key, 32);
    }

    // Deterministic part of EdDSA: Construct a nonce by hashing the message
    // instead of generating a random number.
    // An actual random number would work just fine, and would save us
    // the trouble of hashing the message twice.  If we did that
    // however, the user could fuck it up and reuse the nonce.
    ctx->hash->init  (ctx);
    ctx->hash->update(ctx, prefix , 32);
}

void crypto_sign_init_first_pass(crypto_sign_ctx_abstract *ctx,
                                 const u8 secret_key[32],
                                 const u8 public_key[32])
{
    crypto_sign_init_first_pass_custom_hash(ctx, secret_key, public_key,
                                            &crypto_blake2b_vtable);
}

void crypto_sign_update(crypto_sign_ctx_abstract *ctx,
                        const u8 *msg, size_t msg_size)
{
    ctx->hash->update(ctx, msg, msg_size);
}

void crypto_sign_init_second_pass(crypto_sign_ctx_abstract *ctx)
{
    u8 *r        = ctx->buf + 32;
    u8 *half_sig = ctx->buf + 64;
    ctx->hash->final(ctx, r);
    reduce(r);

    // first half of the signature = "random" nonce times the base point
    ge R;
    ge_scalarmult_base(&R, r);
    ge_tobytes(half_sig, &R);
    WIPE_CTX(&R);

    // Hash R, the public key, and the message together.
    // It cannot be done in parallel with the first hash.
    ctx->hash->init  (ctx);
    ctx->hash->update(ctx, half_sig, 32);
    ctx->hash->update(ctx, ctx->pk , 32);
}

void crypto_sign_final(crypto_sign_ctx_abstract *ctx, u8 signature[64])
{
    u8 *a        = ctx->buf;
    u8 *r        = ctx->buf + 32;
    u8 *half_sig = ctx->buf + 64;
    u8  h_ram[64];
    ctx->hash->final(ctx, h_ram);
    reduce(h_ram);
    COPY(signature, half_sig, 32);
    mul_add(signature + 32, h_ram, a, r); // s = h_ram * a + r
    WIPE_BUFFER(h_ram);
    crypto_wipe(ctx, ctx->hash->ctx_size);
}

void crypto_sign(u8        signature[64],
                 const u8  secret_key[32],
                 const u8  public_key[32],
                 const u8 *message, size_t message_size)
{
    crypto_sign_ctx ctx;
    crypto_sign_ctx_abstract *actx = (crypto_sign_ctx_abstract*)&ctx;
    crypto_sign_init_first_pass (actx, secret_key, public_key);
    crypto_sign_update          (actx, message, message_size);
    crypto_sign_init_second_pass(actx);
    crypto_sign_update          (actx, message, message_size);
    crypto_sign_final           (actx, signature);
}

void crypto_check_init_custom_hash(crypto_check_ctx_abstract *ctx,
                                   const u8 signature[64],
                                   const u8 public_key[32],
                                   const crypto_sign_vtable *hash)
{
    ctx->hash = hash; // set vtable
    COPY(ctx->buf, signature , 64);
    COPY(ctx->pk , public_key, 32);
    ctx->hash->init  (ctx);
    ctx->hash->update(ctx, signature , 32);
    ctx->hash->update(ctx, public_key, 32);
}

void crypto_check_init(crypto_check_ctx_abstract *ctx, const u8 signature[64],
                       const u8 public_key[32])
{
    crypto_check_init_custom_hash(ctx, signature, public_key,
                                  &crypto_blake2b_vtable);
}

void crypto_check_update(crypto_check_ctx_abstract *ctx,
                         const u8 *msg, size_t msg_size)
{
    ctx->hash->update(ctx, msg, msg_size);
}

int crypto_check_final(crypto_check_ctx_abstract *ctx)
{
    u8 h_ram[64];
    ctx->hash->final(ctx, h_ram);
    reduce(h_ram);
    u8 *R       = ctx->buf;      // R
    u8 *s       = ctx->buf + 32; // s
    u8 *R_check = ctx->pk;       // overwrite ctx->pk to save stack space
    if (ge_r_check(R_check, s, h_ram, ctx->pk)) {
        return -1;
    }
    return crypto_verify32(R, R_check); // R == R_check ? OK : fail
}

int crypto_check(const u8  signature[64], const u8 public_key[32],
                 const u8 *message, size_t message_size)
{
    crypto_check_ctx ctx;
    crypto_check_ctx_abstract *actx = (crypto_check_ctx_abstract*)&ctx;
    crypto_check_init  (actx, signature, public_key);
    crypto_check_update(actx, message, message_size);
    return crypto_check_final(actx);
}

///////////////////////
/// EdDSA to X25519 ///
///////////////////////
void crypto_from_eddsa_private(u8 x25519[32], const u8 eddsa[32])
{
    u8 a[64];
    crypto_blake2b(a, eddsa, 32);
    COPY(x25519, a, 32);
    WIPE_BUFFER(a);
}

static const fe fe_one = {1};

void crypto_from_eddsa_public(u8 x25519[32], const u8 eddsa[32])
{
    fe t1, t2;
    fe_frombytes(t2, eddsa);
    fe_add(t1, fe_one, t2);
    fe_sub(t2, fe_one, t2);
    fe_invert(t2, t2);
    fe_mul(t1, t1, t2);
    fe_tobytes(x25519, t1);
    WIPE_BUFFER(t1);
    WIPE_BUFFER(t2);
}

/////////////////////////////////////////////
/// Dirty ephemeral public key generation ///
/////////////////////////////////////////////

// Those functions generates a public key, *without* clearing the
// cofactor.  Sending that key over the network leaks 3 bits of the
// private key.  Use only to generate ephemeral keys that will be hidden
// with crypto_curve_to_hidden().
//
// The public key is otherwise compatible with crypto_x25519() and
// crypto_key_exchange() (those properly clear the cofactor).
//
// Note that the distribution of the resulting public keys is almost
// uniform.  Flipping the sign of the v coordinate (not provided by this
// function), covers the entire key space almost perfectly, where
// "almost" means a 2^-128 bias (undetectable).  This uniformity is
// needed to ensure the proper randomness of the resulting
// representatives (once we apply crypto_curve_to_hidden()).
//
// Recall that Curve25519 has order C = 2^255 + e, with e < 2^128 (not
// to be confused with the prime order of the main subgroup, L, which is
// 8 times less than that).
//
// Generating all points would require us to multiply a point of order C
// (the base point plus any point of order 8) by all scalars from 0 to
// C-1.  Clamping limits us to scalars between 2^254 and 2^255 - 1. But
// by negating the resulting point at random, we also cover scalars from
// -2^255 + 1 to -2^254 (which modulo C is congruent to e+1 to 2^254 + e).
//
// In practice:
// - Scalars from 0         to e + 1     are never generated
// - Scalars from 2^255     to 2^255 + e are never generated
// - Scalars from 2^254 + 1 to 2^254 + e are generated twice
//
// Since e < 2^128, detecting this bias requires observing over 2^100
// representatives from a given source (this will never happen), *and*
// recovering enough of the private key to determine that they do, or do
// not, belong to the biased set (this practically requires solving
// discrete logarithm, which is conjecturally intractable).
//
// In practice, this means the bias is impossible to detect.

// s + (x*L) % 8*L
// Guaranteed to fit in 256 bits iff s fits in 255 bits.
//   L             < 2^253
//   x%8           < 2^3
//   L * (x%8)     < 2^255
//   s             < 2^255
//   s + L * (x%8) < 2^256
static void add_xl(u8 s[32], u8 x)
{
    u32 mod8  = x & 7;
    u32 carry = 0;
    FOR (i , 0, 32) {
        carry = carry + s[i] + L[i] * mod8;
        s[i]  = (u8)carry;
        carry >>= 8;
    }
}

// "Small" dirty ephemeral key.
// Use if you need to shrink the size of the binary, and can afford to
// slow down by a factor of two (compared to the fast version)
//
// This version works by decoupling the cofactor from the main factor.
//
// - The trimmed scalar determines the main factor
// - The clamped bits of the scalar determine the cofactor.
//
// Cofactor and main factor are combined into a single scalar, which is
// then multiplied by a point of order 8*L (unlike the base point, which
// has prime order).  That "dirty" base point is the addition of the
// regular base point (9), and a point of order 8.
void crypto_x25519_dirty_small(u8 public_key[32], const u8 secret_key[32])
{
    // Base point of order 8*L
    // Raw scalar multiplication with it does not clear the cofactor,
    // and the resulting public key will reveal 3 bits of the scalar.
    static const u8 dirty_base_point[32] = {
        0x34, 0xfc, 0x6c, 0xb7, 0xc8, 0xde, 0x58, 0x97, 0x77, 0x70, 0xd9, 0x52,
        0x16, 0xcc, 0xdc, 0x6c, 0x85, 0x90, 0xbe, 0xcd, 0x91, 0x9c, 0x07, 0x59,
        0x94, 0x14, 0x56, 0x3b, 0x4b, 0xa4, 0x47, 0x0f, };
    // separate the main factor & the cofactor of the scalar
    u8 scalar[32];
    trim_scalar(scalar, secret_key);

    // Separate the main factor and the cofactor
    //
    // The scalar is trimmed, so its cofactor is cleared.  The three
    // least significant bits however still have a main factor.  We must
    // remove it for X25519 compatibility.
    //
    // We exploit the fact that 5*L = 1 (modulo 8)
    //   cofactor = lsb * 5 * L             (modulo 8*L)
    //   combined = scalar + cofactor       (modulo 8*L)
    //   combined = scalar + (lsb * 5 * L)  (modulo 8*L)
    add_xl(scalar, secret_key[0] * 5);
    scalarmult(public_key, scalar, dirty_base_point, 256);
    WIPE_BUFFER(scalar);
}

// "Fast" dirty ephemeral key
// We use this one by default.
//
// This version works by performing a regular scalar multiplication,
// then add a low order point.  The scalar multiplication is done in
// Edwards space for more speed (*2 compared to the "small" version).
// The cost is a bigger binary for programs that don't also sign messages.
void crypto_x25519_dirty_fast(u8 public_key[32], const u8 secret_key[32])
{
    static const fe lop_x ={21352778, 5345713, 4660180, -8347857, 24143090,
                            14568123, 30185756, -12247770, -33528939, 8345319,};
    static const fe lop_y ={-6952922, -1265500, 6862341, -7057498, -4037696,
                            -5447722, 31680899, -15325402, -19365852, 1569102,};
    u8 scalar[32];
    ge pk;
    trim_scalar(scalar, secret_key);
    ge_scalarmult_base(&pk, scalar);

    // Select low order point
    // We're computing the [cofactor]lop scalar multiplication, where:
    //   cofactor = tweak & 7.
    //   lop      = (lop_x, lop_y)
    //   lop_x    = sqrt((sqrt(d + 1) + 1) / d)
    //   lop_y    = -lop_x * sqrtm1
    // Notes:
    // - A (single) Montgomery ladder would be twice as slow.
    // - An actual scalar multiplication would hurt performance.
    // - A full table lookup would take more code.
    u8 cofactor = secret_key[0] & 7;
    int a = (cofactor >> 2) & 1;
    int b = (cofactor >> 1) & 1;
    int c = (cofactor >> 0) & 1;
    fe t1, t2, t3;
    fe_0(t1);
    fe_ccopy(t1, sqrtm1, b);
    fe_ccopy(t1, lop_x , c);
    fe_neg  (t3, t1);
    fe_ccopy(t1, t3, a);
    fe_1(t2);
    fe_0(t3);
    fe_ccopy(t2, t3   , b);
    fe_ccopy(t2, lop_y, c);
    fe_neg  (t3, t2);
    fe_ccopy(t2, t3, a^b);
    ge_precomp low_order_point;
    fe_add(low_order_point.Yp, t2, t1);
    fe_sub(low_order_point.Ym, t2, t1);
    fe_mul(low_order_point.T2, t2, t1);
    fe_mul(low_order_point.T2, low_order_point.T2, D2);

    // Add low order point to the public key
    ge_madd(&pk, &pk, &low_order_point, t1, t2);

    // Convert to Montgomery u coordinate (we ignore the sign)
    fe_add(t1, pk.Z, pk.Y);
    fe_sub(t2, pk.Z, pk.Y);
    fe_invert(t2, t2);
    fe_mul(t1, t1, t2);

    fe_tobytes(public_key, t1);

    WIPE_BUFFER(t1);  WIPE_BUFFER(scalar);
    WIPE_BUFFER(t2);  WIPE_CTX(&pk);
    WIPE_BUFFER(t3);  WIPE_CTX(&low_order_point);
}

///////////////////
/// Elligator 2 ///
///////////////////
static const fe A = {486662};

// Elligator direct map
//
// Computes the point corresponding to a representative, encoded in 32
// bytes (little Endian).  Since positive representatives fits in 254
// bits, The two most significant bits are ignored.
//
// From the paper:
// w = -A / (fe(1) + non_square * r^2)
// e = chi(w^3 + A*w^2 + w)
// u = e*w - (fe(1)-e)*(A//2)
// v = -e * sqrt(u^3 + A*u^2 + u)
//
// We ignore v because we don't need it for X25519 (the Montgomery
// ladder only uses u).
//
// Note that e is either 0, 1 or -1
// if e = 0    u = 0  and v = 0
// if e = 1    u = w
// if e = -1   u = -w - A = w * non_square * r^2
//
// Let r1 = non_square * r^2
// Let r2 = 1 + r1
// Note that r2 cannot be zero, -1/non_square is not a square.
// We can (tediously) verify that:
//   w^3 + A*w^2 + w = (A^2*r1 - r2^2) * A / r2^3
// Therefore:
//   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) * (A / r2^3))
//   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) * (A / r2^3)) * 1
//   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) * (A / r2^3)) * chi(r2^6)
//   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) * (A / r2^3)  *     r2^6)
//   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) *  A * r2^3)
// Corollary:
//   e =  1 if (A^2*r1 - r2^2) *  A * r2^3) is a non-zero square
//   e = -1 if (A^2*r1 - r2^2) *  A * r2^3) is not a square
//   Note that w^3 + A*w^2 + w (and therefore e) can never be zero:
//     w^3 + A*w^2 + w = w * (w^2 + A*w + 1)
//     w^3 + A*w^2 + w = w * (w^2 + A*w + A^2/4 - A^2/4 + 1)
//     w^3 + A*w^2 + w = w * (w + A/2)^2        - A^2/4 + 1)
//     which is zero only if:
//       w = 0                   (impossible)
//       (w + A/2)^2 = A^2/4 - 1 (impossible, because A^2/4-1 is not a square)
//
// Let isr   = invsqrt((A^2*r1 - r2^2) *  A * r2^3)
//     isr   = sqrt(1        / ((A^2*r1 - r2^2) *  A * r2^3)) if e =  1
//     isr   = strt(sqrt(-1) / ((A^2*r1 - r2^2) *  A * r2^3)) if e = -1
//
// if e = 1
//   let u1 = -A * (A^2*r1 - r2^2) * A * r2^2 * isr^2
//       u1 = w
//       u1 = u
//
// if e = -1
//   let ufactor = -non_square * sqrt(-1) * r^2
//   let vfactor = sqrt(ufactor)
//   let u2 = -A * (A^2*r1 - r2^2) * A * r2^2 * isr^2 * ufactor
//       u2 = w * -1 * -non_square * r^2
//       u2 = w * non_square * r^2
//       u2 = u
void crypto_hidden_to_curve(uint8_t curve[32], const uint8_t hidden[32])
{
     // -sqrt(-1) * 2
    static const fe ufactor={-1917299, 15887451, -18755900, -7000830, -24778944,
                             544946, -16816446, 4011309, -653372, 10741468,};
    static const fe A2 = {12721188, 3529,};

    // Representatives are encoded in 254 bits.
    // The two most significant ones are random padding that must be ignored.
    u8 clamped[32];
    COPY(clamped, hidden, 32);
    clamped[31] &= 0x3f;

    fe r, u, t1, t2, t3;
    fe_frombytes(r, clamped);
    fe_sq2(t1, r);
    fe_add(u, t1, fe_one);
    fe_sq (t2, u);
    fe_mul(t3, A2, t1);
    fe_sub(t3, t3, t2);
    fe_mul(t3, t3, A);
    fe_mul(t1, t2, u);
    fe_mul(t1, t3, t1);
    int is_square = invsqrt(t1, t1);
    fe_sq(u, r);
    fe_mul(u, u, ufactor);
    fe_ccopy(u, fe_one, is_square);
    fe_sq (t1, t1);
    fe_mul(u, u, A);
    fe_mul(u, u, t3);
    fe_mul(u, u, t2);
    fe_mul(u, u, t1);
    fe_neg(u, u);
    fe_tobytes(curve, u);

    WIPE_BUFFER(t1);  WIPE_BUFFER(r);
    WIPE_BUFFER(t2);  WIPE_BUFFER(u);
    WIPE_BUFFER(t3);  WIPE_BUFFER(clamped);
}

// Elligator inverse map
//
// Computes the representative of a point, if possible.  If not, it does
// nothing and returns -1.  Note that the success of the operation
// depends only on the point (more precisely its u coordinate).  The
// tweak parameter is used only upon success
//
// The tweak should be a random byte.  Beyond that, its contents are an
// implementation detail. Currently, the tweak comprises:
// - Bit  1  : sign of the v coordinate (0 if positive, 1 if negative)
// - Bit  2-5: not used
// - Bits 6-7: random padding
//
// From the paper:
// Let sq = -non_square * u * (u+A)
// if sq is not a square, or u = -A, there is no mapping
// Assuming there is a mapping:
//   if v is positive: r = sqrt(-(u+A) / u)
//   if v is negative: r = sqrt(-u / (u+A))
//
// We compute isr = invsqrt(-non_square * u * (u+A))
// if it wasn't a non-zero square, abort.
// else, isr = sqrt(-1 / (non_square * u * (u+A))
//
// This causes us to abort if u is zero, even though we shouldn't. This
// never happens in practice, because (i) a random point in the curve has
// a negligible chance of being zero, and (ii) scalar multiplication with
// a trimmed scalar *never* yields zero.
//
// Since:
//   isr * (u+A) = sqrt(-1     / (non_square * u * (u+A)) * (u+A)
//   isr * (u+A) = sqrt(-(u+A) / (non_square * u * (u+A))
// and:
//   isr = u = sqrt(-1 / (non_square * u * (u+A)) * u
//   isr = u = sqrt(-u / (non_square * u * (u+A))
// Therefore:
//   if v is positive: r = isr * (u+A)
//   if v is negative: r = isr * u
int crypto_curve_to_hidden(u8 hidden[32], const u8 public_key[32], u8 tweak)
{
    fe t1, t2, t3;
    fe_frombytes(t1, public_key);

    fe_add(t2, t1, A);
    fe_mul(t3, t1, t2);
    fe_mul_small(t3, t3, -2);
    int is_square = invsqrt(t3, t3);
    if (!is_square) {
        // The only variable time bit.  This ultimately reveals how many
        // tries it took us to find a representable key.
        // This does not affect security as long as we try keys at random.
        WIPE_BUFFER(t1);
        WIPE_BUFFER(t2);
        WIPE_BUFFER(t3);
        return -1;
    }
    fe_ccopy(t1, t2, tweak & 1);
    fe_mul  (t3, t1, t3);
    fe_add  (t1, t3, t3);
    fe_neg  (t2, t3);
    fe_ccopy(t3, t2, fe_isodd(t1));
    fe_tobytes(hidden, t3);

    // Pad with two random bits
    hidden[31] |= tweak & 0xc0;

    WIPE_BUFFER(t1);
    WIPE_BUFFER(t2);
    WIPE_BUFFER(t3);
    return 0;
}

void crypto_hidden_key_pair(u8 hidden[32], u8 secret_key[32], u8 seed[32])
{
    u8 pk [32]; // public key
    u8 buf[64]; // seed + representative
    COPY(buf + 32, seed, 32);
    do {
        crypto_chacha20(buf, 0, 64, buf+32, zero);
        crypto_x25519_dirty_fast(pk, buf); // or the "small" version
    } while(crypto_curve_to_hidden(buf+32, pk, buf[32]));
    // Note that the return value of crypto_curve_to_hidden() is
    // independent from its tweak parameter.
    // Therefore, buf[32] is not actually reused.  Either we loop one
    // more time and buf[32] is used for the new seed, or we succeeded,
    // and buf[32] becomes the tweak parameter.

    crypto_wipe(seed, 32);
    COPY(hidden    , buf + 32, 32);
    COPY(secret_key, buf     , 32);
    WIPE_BUFFER(buf);
    WIPE_BUFFER(pk);
}

////////////////////
/// Key exchange ///
////////////////////
void crypto_key_exchange(u8       shared_key[32],
                         const u8 your_secret_key [32],
                         const u8 their_public_key[32])
{
    crypto_x25519(shared_key, your_secret_key, their_public_key);
    crypto_hchacha20(shared_key, shared_key, zero);
}

///////////////////////
/// Scalar division ///
///////////////////////
static void multiply(u32 p[16], const u32 a[8], const u32 b[8])
{
    ZERO(p, 16);
    FOR (i, 0, 8) {
        u64 carry = 0;
        FOR (j, 0, 8) {
            carry  += p[i+j] + (u64)a[i] * b[j];
            p[i+j]  = (u32)carry;
            carry >>= 32;
        }
        p[i+8] = (u32)carry;
    }
}

// Montgomery reduction.
// Divides x by (2^256), and reduces the result modulo L
//
// Precondition:
//   x < L * 2^256
// Constants:
//   r = 2^256                 (makes division by r trivial)
//   k = (r * (1/r) - 1) // L  (1/r is computed modulo L   )
// Algorithm:
//   s = (x * k) % r
//   t = x + s*L      (t is always a multiple of r)
//   u = (t/r) % L    (u is always below 2*L, conditional subtraction is enough)
static void redc(u32 u[8], u32 x[16])
{
    static const u32 k[8]  = { 0x12547e1b, 0xd2b51da3, 0xfdba84ff, 0xb1a206f2,
                               0xffa36bea, 0x14e75438, 0x6fe91836, 0x9db6c6f2,};
    static const u32 l[8]  = { 0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de,
                               0x00000000, 0x00000000, 0x00000000, 0x10000000,};
    // s = x * k (modulo 2^256)
    // This is cheaper than the full multiplication.
    u32 s[8] = {0};
    FOR (i, 0, 8) {
        u64 carry = 0;
        FOR (j, 0, 8-i) {
            carry  += s[i+j] + (u64)x[i] * k[j];
            s[i+j]  = (u32)carry;
            carry >>= 32;
        }
    }
    u32 t[16];
    multiply(t, s, l);

    // t = t + x
    u64 carry = 0;
    FOR (i, 0, 16) {
        carry  += (u64)t[i] + x[i];
        t[i]    = (u32)carry;
        carry >>= 32;
    }

    // u = (t / 2^256) % L
    // Note that t / 2^256 is always below 2*L,
    // So a constant time conditional subtraction is enough
    // We work with L directly, in a 2's complement encoding
    // (-L == ~L + 1)
    carry = 1;
    FOR (i, 0, 8) {
        carry  += (u64)t[i+8] + ~l[i];
        carry >>= 32;
    }
    u32 mask = (u32)-carry; // carry == 0 or 1
    FOR (i, 0, 8) {
        carry  += (u64)t[i+8] + (~l[i] & mask);
        u[i]    = (u32)carry;
        carry >>= 32;
    }
    WIPE_BUFFER(s);
    WIPE_BUFFER(t);
}

void crypto_x25519_inverse(u8 blind_salt [32], const u8 private_key[32],
                           const u8 curve_point[32])
{
    static const  u8 Lm2[32] = { // L - 2
        0xeb, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
        0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, };
    // 1 in Montgomery form
    u32 m_inv [8] = {0x8d98951d, 0xd6ec3174, 0x737dcf70, 0xc6ef5bf4,
                     0xfffffffe, 0xffffffff, 0xffffffff, 0x0fffffff,};

    u8 scalar[32];
    trim_scalar(scalar, private_key);

    // Convert the scalar in Montgomery form
    // m_scl = scalar * 2^256 (modulo L)
    u32 m_scl[8];
    {
        i64 tmp[64];
        ZERO(tmp, 32);
        COPY(tmp+32, scalar, 32);
        modL(scalar, tmp);
        load32_le_buf(m_scl, scalar, 8);
        WIPE_BUFFER(tmp); // Wipe ASAP to save stack space
    }

    u32 product[16];
    for (int i = 252; i >= 0; i--) {
        multiply(product, m_inv, m_inv);
        redc(m_inv, product);
        if (scalar_bit(Lm2, i)) {
            multiply(product, m_inv, m_scl);
            redc(m_inv, product);
        }
    }
    // Convert the inverse *out* of Montgomery form
    // scalar = m_inv / 2^256 (modulo L)
    COPY(product, m_inv, 8);
    ZERO(product + 8, 8);
    redc(m_inv, product);
    store32_le_buf(scalar, m_inv, 8); // the *inverse* of the scalar

    // Clear the cofactor of scalar:
    //   cleared = scalar * (3*L + 1)      (modulo 8*L)
    //   cleared = scalar + scalar * 3 * L (modulo 8*L)
    // Note that (scalar * 3) is reduced modulo 8, so we only need the
    // first byte.
    add_xl(scalar, scalar[0] * 3);

    // Recall that 8*L < 2^256. However it is also very close to
    // 2^255. If we spanned the ladder over 255 bits, random tests
    // wouldn't catch the off-by-one error.
    scalarmult(blind_salt, scalar, curve_point, 256);

    WIPE_BUFFER(scalar);   WIPE_BUFFER(m_scl);
    WIPE_BUFFER(product);  WIPE_BUFFER(m_inv);
}

////////////////////////////////
/// Authenticated encryption ///
////////////////////////////////
static void lock_auth(u8 mac[16], const u8  auth_key[32],
                      const u8 *ad         , size_t ad_size,
                      const u8 *cipher_text, size_t text_size)
{
    u8 sizes[16]; // Not secret, not wiped
    store64_le(sizes + 0, ad_size);
    store64_le(sizes + 8, text_size);
    crypto_poly1305_ctx poly_ctx;           // auto wiped...
    crypto_poly1305_init  (&poly_ctx, auth_key);
    crypto_poly1305_update(&poly_ctx, ad         , ad_size);
    crypto_poly1305_update(&poly_ctx, zero       , ALIGN(ad_size, 16));
    crypto_poly1305_update(&poly_ctx, cipher_text, text_size);
    crypto_poly1305_update(&poly_ctx, zero       , ALIGN(text_size, 16));
    crypto_poly1305_update(&poly_ctx, sizes      , 16);
    crypto_poly1305_final (&poly_ctx, mac); // ...here
}

void crypto_lock_aead(u8 mac[16], u8 *cipher_text,
                      const u8  key[32], const u8  nonce[24],
                      const u8 *ad        , size_t ad_size,
                      const u8 *plain_text, size_t text_size)
{
    u8 sub_key[32];
    u8 auth_key[64]; // "Wasting" the whole Chacha block is faster
    crypto_hchacha20(sub_key, key, nonce);
    crypto_chacha20(auth_key, 0, 64, sub_key, nonce + 16);
    crypto_chacha20_ctr(cipher_text, plain_text, text_size,
                        sub_key, nonce + 16, 1);
    lock_auth(mac, auth_key, ad, ad_size, cipher_text, text_size);
    WIPE_BUFFER(sub_key);
    WIPE_BUFFER(auth_key);
}

int crypto_unlock_aead(u8 *plain_text, const u8 key[32], const u8 nonce[24],
                       const u8  mac[16],
                       const u8 *ad         , size_t ad_size,
                       const u8 *cipher_text, size_t text_size)
{
    u8 sub_key[32];
    u8 auth_key[64]; // "Wasting" the whole Chacha block is faster
    crypto_hchacha20(sub_key, key, nonce);
    crypto_chacha20(auth_key, 0, 64, sub_key, nonce + 16);
    u8 real_mac[16];
    lock_auth(real_mac, auth_key, ad, ad_size, cipher_text, text_size);
    WIPE_BUFFER(auth_key);
    if (crypto_verify16(mac, real_mac)) {
        WIPE_BUFFER(sub_key);
        WIPE_BUFFER(real_mac);
        return -1;
    }
    crypto_chacha20_ctr(plain_text, cipher_text, text_size,
                        sub_key, nonce + 16, 1);
    WIPE_BUFFER(sub_key);
    WIPE_BUFFER(real_mac);
    return 0;
}

void crypto_lock(u8 mac[16], u8 *cipher_text,
                 const u8 key[32], const u8 nonce[24],
                 const u8 *plain_text, size_t text_size)
{
    crypto_lock_aead(mac, cipher_text, key, nonce, 0, 0, plain_text, text_size);
}

int crypto_unlock(u8 *plain_text,
                  const u8 key[32], const u8 nonce[24], const u8 mac[16],
                  const u8 *cipher_text, size_t text_size)
{
    return crypto_unlock_aead(plain_text, key, nonce, mac, 0, 0,
                              cipher_text, text_size);
}
