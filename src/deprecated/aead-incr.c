// Deprecated incremental API for authenticated encryption
//
// This file *temporarily* provides compatibility with Monocypher 2.x.
// Do not rely on its continued existence.
//
// Deprecated in     : 3.0.0
// Will be removed in: 4.0.0
//
// Deprecated functions & types:
//     crypto_unlock_ctx
//     crypto_lock_ctx
//     crypto_lock_init
//     crypto_lock_auth_ad
//     crypto_lock_auth_message
//     crypto_lock_update
//     crypto_lock_final
//     crypto_unlock_init
//     crypto_unlock_auth_ad
//     crypto_unlock_auth_message
//     crypto_unlock_update
//     crypto_unlock_final
//
// For existing deployments that can no longer be updated or modified,
// use the 2.x family, which will receive security updates until 2024.
//
// upgrade strategy:
// Change your protocol in a way that it does not rely on the removed
// functions, namely by splitting the file into chunks you each use the
// crypto_lock() and crypto_unlock() functions on.
//
// For files, you may alternatively (and suboptimally) attempt to
// mmap()/MapViewOfFile() and pass the files as mapped memory into
// crypto_lock() and crypto_unlock() this way instead.
//
// ---
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
// Copyright (c) 2017-2019, Loup Vaillant
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
// Written in 2017-2019 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#include "aead-incr.h"

#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
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

static const u8 zero[16] = {0};

static void store64_le(u8 out[8], u64 in)
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
    out[4] = (in >> 32) & 0xff;
    out[5] = (in >> 40) & 0xff;
    out[6] = (in >> 48) & 0xff;
    out[7] = (in >> 56) & 0xff;
}

////////////////////////////////////
/// Incremental API for Chacha20 ///
////////////////////////////////////
static void chacha20_x_init(crypto_lock_ctx *ctx,
                            const u8 key[32], const u8 nonce[24])
{
    crypto_hchacha20(ctx->key, key, nonce);
    FOR (i, 0,  8) { ctx->nonce[i] = nonce[i + 16]; }
    ctx->ctr = 0;
    ctx->pool_idx = 64; // The random pool starts empty
}

static void chacha20_encrypt(crypto_lock_ctx *ctx, u8 *cipher_text,
                             const u8 *plain_text, size_t text_size)
{
    FOR (i, 0, text_size) {
        if (ctx->pool_idx == 64) {
            crypto_chacha20_ctr(ctx->pool, 0, 64,
                                ctx->key, ctx-> nonce, ctx->ctr);
            ctx->pool_idx = 0;
            ctx->ctr++;
        }
        u8 plain = 0;
        if (plain_text != 0) {
            plain = *plain_text;
            plain_text++;
        }
        *cipher_text = ctx->pool[ctx->pool_idx] ^ plain;
        ctx->pool_idx++;
        cipher_text++;
    }
}

static void chacha20_stream(crypto_lock_ctx *ctx, u8 *stream, size_t size)
{
    chacha20_encrypt(ctx, stream, 0, size);
}


////////////////////////////////
/// Incremental API for AEAD ///
////////////////////////////////
static void lock_ad_padding(crypto_lock_ctx *ctx)
{
    if (ctx->ad_phase) {
        ctx->ad_phase = 0;
        crypto_poly1305_update(&ctx->poly, zero, ALIGN(ctx->ad_size, 16));
    }
}

void crypto_lock_init(crypto_lock_ctx *ctx,
                      const u8 key[32], const u8 nonce[24])
{
    u8 auth_key[64]; // "Wasting" the whole Chacha block is faster
    ctx->ad_phase     = 1;
    ctx->ad_size      = 0;
    ctx->message_size = 0;
    chacha20_x_init(ctx, key, nonce);
    chacha20_stream(ctx, auth_key, 64);
    crypto_poly1305_init  (&ctx->poly  , auth_key);
    WIPE_BUFFER(auth_key);
}

void crypto_lock_auth_ad(crypto_lock_ctx *ctx, const u8 *msg, size_t msg_size)
{
    crypto_poly1305_update(&ctx->poly, msg, msg_size);
    ctx->ad_size += msg_size;
}

void crypto_lock_auth_message(crypto_lock_ctx *ctx,
                              const u8 *cipher_text, size_t text_size)
{
    lock_ad_padding(ctx);
    ctx->message_size += text_size;
    crypto_poly1305_update(&ctx->poly, cipher_text, text_size);
}

void crypto_lock_update(crypto_lock_ctx *ctx, u8 *cipher_text,
                        const u8 *plain_text, size_t text_size)
{
    chacha20_encrypt(ctx, cipher_text, plain_text, text_size);
    crypto_lock_auth_message(ctx, cipher_text, text_size);
}

void crypto_lock_final(crypto_lock_ctx *ctx, u8 mac[16])
{
    lock_ad_padding(ctx);
    u8 sizes[16]; // Not secret, not wiped
    store64_le(sizes + 0, ctx->ad_size);
    store64_le(sizes + 8, ctx->message_size);
    crypto_poly1305_update(&ctx->poly, zero, ALIGN(ctx->message_size, 16));
    crypto_poly1305_update(&ctx->poly, sizes, 16);
    crypto_poly1305_final (&ctx->poly, mac);
    WIPE_CTX(ctx);
}

void crypto_unlock_update(crypto_lock_ctx *ctx, u8 *plain_text,
                          const u8 *cipher_text, size_t text_size)
{
    crypto_unlock_auth_message(ctx, cipher_text, text_size);
    chacha20_encrypt(ctx, plain_text, cipher_text, text_size);
}

int crypto_unlock_final(crypto_lock_ctx *ctx, const u8 mac[16])
{
    u8 real_mac[16];
    crypto_lock_final(ctx, real_mac);
    int mismatch = crypto_verify16(real_mac, mac);
    WIPE_BUFFER(real_mac);
    return mismatch;
}
