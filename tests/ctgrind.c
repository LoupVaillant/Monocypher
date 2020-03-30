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
// Copyright (c) 2020, Loup Vaillant
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
// Written in 2020 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "utils.h"

static void verify16()
{
    u8 a[16];
    u8 b[16];
    crypto_verify16(a, b);
}

static void verify32()
{
    u8 a[32];
    u8 b[32];
    crypto_verify32(a, b);
}

static void verify64()
{
    u8 a[64];
    u8 b[64];
    crypto_verify64(a, b);
}

static void wipe()
{
    FOR (i, 0, 128) {
        u8 secret[128];
        crypto_wipe(secret, i);
    }
}

static void lock_aead()
{
    FOR(i, 0, 128) {
        u8 mac        [ 16];
        u8 cipher_text[128];
        u8 key        [ 32];
        u8 nonce      [ 24];
        u8 ad         [128];
        u8 plain_text [128];
        crypto_lock_aead(mac, cipher_text, key, nonce, ad, i, plain_text, i);
    }
}

static void unlock_aead()
{
    FOR(i, 0, 128) {
        u8 plain_text [128];
        u8 key        [ 32];
        u8 nonce      [ 24];
        u8 mac        [ 16];
        u8 ad         [128];
        u8 cipher_text[128];
        crypto_unlock_aead(plain_text, key, nonce, mac, ad, i, cipher_text, i);
    }
}

static void blake2b_general()
{
    FOR (i, 0, 256) {
        u8 hash   [ 64];
        u8 key    [ 64];
        u8 message[256];
        crypto_blake2b_general(hash, 64, key, 0, message, i);
    }
    FOR (i, 0, 64) {
        u8 hash   [ 64];
        u8 key    [ 64];
        u8 message[256];
        crypto_blake2b_general(hash, 64, key, i, message, 128);
    }
    FOR (i, 0, 64) {
        u8 hash   [ 64];
        u8 key    [ 64];
        u8 message[256];
        crypto_blake2b_general(hash, i, key, 0, message, 0);
    }
}

static void argon2i_general()
{
    void *work_area = alloc(1024 * 600);
    u8    hash    [ 32];
    u8    password[ 16];
    u8    salt    [ 16];
    u8    key     [ 32];
    u8    ad      [128];
    crypto_argon2i_general(hash, 32, work_area, 600, 3,
                           password, 16, salt, 16, key, 32, ad, 128);
    free(work_area);
}

static void key_exchange()
{
    u8 shared_key      [32];
    u8 your_secret_key [32];
    u8 their_public_key[32];
    crypto_key_exchange(shared_key, your_secret_key, their_public_key);
}

static void sign_public_key()
{
    u8  public_key[32];
    u8  secret_key[32];
    crypto_sign_public_key(public_key, secret_key);
}

static void sign()
{
    u8  signature [64];
    u8  secret_key[32];
    u8  public_key[32];
    u8  message   [64];
    crypto_sign(signature, secret_key, public_key, message, 64);
}

static void from_eddsa_private()
{
    u8 x25519[32];
    u8 eddsa [32];
    crypto_from_eddsa_private(x25519, eddsa);
}
static void from_eddsa_public()
{
    u8 x25519[32];
    u8 eddsa [32];
    crypto_from_eddsa_public(x25519, eddsa);
}

static void hidden_to_curve()
{
    u8 curve [32];
    u8 hidden[32];
    crypto_hidden_to_curve(curve, hidden);
}

static void curve_to_hidden()
{
    u8 hidden[32];
    u8 curve [32];
    u8 tweak; // The compiler notices this one is used uninitialised
    crypto_curve_to_hidden(hidden, curve, tweak);
}

static void hidden_key_pair()
{
    u8 hidden    [32];
    u8 secret_key[32];
    u8 seed      [32];
    crypto_hidden_key_pair(hidden, secret_key,seed);
}

static void h_chacha20()
{
    u8 out[32], key[32], in[16];
    crypto_hchacha20(out, key, in);
}

static void chacha20()
{
    FOR (i, 0, 128) {
        u8 cipher_text[128];
        u8 plain_text [128];
        u8 key        [ 32];
        u8 nonce      [  8];
        crypto_chacha20(cipher_text, plain_text, i,  key, nonce);
    }
}
static void xchacha20()
{
    FOR (i, 0, 128) {
        u8 cipher_text[128];
        u8 plain_text [128];
        u8 key        [ 32];
        u8 nonce      [ 24];
        crypto_xchacha20(cipher_text, plain_text, i,  key, nonce);
    }
}
static void ietf_chacha20()
{
    FOR (i, 0, 128) {
        u8 cipher_text[128];
        u8 plain_text [128];
        u8 key        [ 32];
        u8 nonce      [ 12];
        crypto_ietf_chacha20(cipher_text, plain_text, i,  key, nonce);
    }
}

static void poly1305()
{
    FOR (i, 0, 32) {
        u8 mac     [16];
        u8 message [32];
        u8 key     [32];
        crypto_poly1305(mac, message, i, key);
    }
}

static void x25519_dirty_small()
{
    u8 pk[32];
    u8 sk[32];
    crypto_x25519_dirty_small(pk, sk);
}
static void x25519_dirty_fast()
{
    u8 pk[32];
    u8 sk[32];
    crypto_x25519_dirty_fast(pk, sk);
}

static void x25519_inverse()
{
    u8 blind_salt [32];
    u8 private_key[32];
    u8 curve_point[32];
    crypto_x25519_inverse(blind_salt, private_key, curve_point);
}


#define RUN(f, s) printf("%s: crypto_"#f"\n", s); f()

int main()
{
    RUN(verify16          , "constant time");
    RUN(verify32          , "constant time");
    RUN(verify64          , "constant time");
    RUN(wipe              , "constant time");
    RUN(lock_aead         , "constant time");
    RUN(unlock_aead       , "1 conditional");
    RUN(blake2b_general   , "constant time");
    RUN(argon2i_general   , "constant time");
    RUN(key_exchange      , "constant time");
    RUN(sign_public_key   , "constant time");
    RUN(sign              , "constant time");
    printf(                 "skipped      : crypto_check.\n");
    RUN(from_eddsa_private, "constant time");
    RUN(from_eddsa_public , "constant time");
    RUN(hidden_to_curve   , "constant time");
    RUN(curve_to_hidden   , "1 conditional");
    RUN(hidden_key_pair   , "1 conditional"); // shouldn't that be 2?
    RUN(h_chacha20        , "constant time");
    RUN(chacha20          , "constant time");
    RUN(xchacha20         , "constant time");
    RUN(ietf_chacha20     , "constant time");
    RUN(poly1305          , "constant time");
    RUN(x25519_dirty_small, "constant time");
    RUN(x25519_dirty_fast , "constant time");
    RUN(x25519_inverse    , "constant time");

    return 0;
}
