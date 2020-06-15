// Deprecated incremental API for Chacha20
//
// This file *temporarily* provides compatibility with Monocypher 2.x.
// Do not rely on its continued existence.
//
// Deprecated in     : 3.0.0
// Will be removed in: 4.0.0
//
// Deprecated functions & types:
//     crypto_chacha_ctx
//     crypto_chacha20_H
//     crypto_chacha20_init
//     crypto_chacha20_x_init
//     crypto_chacha20_set_ctr
//     crypto_chacha20_encrypt
//     crypto_chacha20_stream
//
// For existing deployments that can no longer be updated or modified,
// use the 2.x family, which will receive security updates until 2024.
//
// Upgrade strategy:
// The new 3.x API can emulate incremental capabilities by setting a
// custom counter.  Make sure you authenticate each chunk before you
// decrypt them, though.
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

#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

// Chacha20
typedef struct {
    uint8_t  key[32];
    uint8_t  nonce[8];
    uint64_t ctr;
    uint8_t  pool[64];
    size_t   pool_idx;
} crypto_chacha_ctx;

// Chacha20 (old API)
// ------------------

// Specialised hash.
void crypto_chacha20_H(uint8_t       out[32],
                       const uint8_t key[32],
                       const uint8_t in [16]);

void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                          const uint8_t      key[32],
                          const uint8_t      nonce[8]);

void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                            const uint8_t      key[32],
                            const uint8_t      nonce[24]);

void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, uint64_t ctr);

void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                             uint8_t           *cipher_text,
                             const uint8_t     *plain_text,
                             size_t             text_size);

void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
                            uint8_t *stream, size_t size);

#ifdef __cplusplus
}
#endif

#endif // CHACHA20_H
