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

#ifndef AEAD_INCR_H
#define AEAD_INCR_H

#include <stddef.h>
#include <inttypes.h>
#include "monocypher.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    crypto_poly1305_ctx poly;
    uint64_t            ad_size;
    uint64_t            message_size;
    int                 ad_phase;
    // Chacha20 context
    uint8_t  key[32];
    uint8_t  nonce[8];
    uint64_t ctr;
    uint8_t  pool[64];
    size_t   pool_idx;
} crypto_lock_ctx;
#define crypto_unlock_ctx crypto_lock_ctx

// Encryption
void crypto_lock_init(crypto_lock_ctx *ctx,
                      const uint8_t    key[32],
                      const uint8_t    nonce[24]);
void crypto_lock_auth_ad(crypto_lock_ctx *ctx,
                         const uint8_t   *message,
                         size_t           message_size);
void crypto_lock_auth_message(crypto_lock_ctx *ctx,
                              const uint8_t *cipher_text, size_t text_size);
void crypto_lock_update(crypto_lock_ctx *ctx,
                        uint8_t         *cipher_text,
                        const uint8_t   *plain_text,
                        size_t           text_size);
void crypto_lock_final(crypto_lock_ctx *ctx, uint8_t mac[16]);

// Decryption
#define crypto_unlock_init         crypto_lock_init
#define crypto_unlock_auth_ad      crypto_lock_auth_ad
#define crypto_unlock_auth_message crypto_lock_auth_message
void crypto_unlock_update(crypto_unlock_ctx *ctx,
                          uint8_t           *plain_text,
                          const uint8_t     *cipher_text,
                          size_t             text_size);
int crypto_unlock_final(crypto_unlock_ctx *ctx, const uint8_t mac[16]);

#ifdef __cplusplus
}
#endif

#endif // AEAD_INCR_H
