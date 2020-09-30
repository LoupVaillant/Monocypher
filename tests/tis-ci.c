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
// Copyright (c) 2020, Mike Pechkin
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
// Written in 2017-2020 by Mike Pechkin
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

#include "monocypher.h"
#include "monocypher-ed25519.h"

typedef uint8_t u8;

#define ARRAY(name, size)                               \
    u8 name[size];                                      \
    for(size_t i = 0; i < size; i++) name[i] = i;

void p1305(void) {
    ARRAY(mac, 16);
    ARRAY(key, 32);
    ARRAY(in,  64);
    for(size_t i = 0; i < 64; i++)
        crypto_poly1305(mac, in, i, key);
}

void blake2b(void) {
    ARRAY(hash, 64);
    ARRAY(key,  64);
    ARRAY(in,   64);

    for(size_t h = 1; h < 64; h += 8)
        for(size_t k = 0; k < 64; k += 8)
            for(size_t i = 0; i < 64; i += 8)
                crypto_blake2b_general(hash, h, key, k, in, i);
}

void verify(void) {
    ARRAY(a, 64);
    ARRAY(b, 64);
    crypto_verify16(a, b);
    crypto_verify32(a, b);
    crypto_verify64(a, b);
}

void wipe(void) {
    ARRAY(a, 64);
    for(size_t i = 0; i < 64; i++)
        crypto_wipe(a, i);
}

void lock_unlock(void) {
    ARRAY(mac,   16);
    ARRAY(enc,   64);
    ARRAY(txt,   64);
    ARRAY(key,   33);
    ARRAY(nonce, 25);
    for(size_t i = 0; i < 64; i++) {
        crypto_lock  (mac, enc, key, nonce, txt, i);
        crypto_unlock(txt, key, nonce, mac, enc, i);
    }
}

void argon(void) {
    ARRAY(hash, 16);
    ARRAY(wrk,  16384); // 16 * 1024
    ARRAY(pwd,  16);
    ARRAY(key,  16);
    ARRAY(slt,  16);
    ARRAY(ad,   16);
    crypto_argon2i_general(hash, 16, wrk, 16, 3, pwd, 16, slt, 16, key, 16, ad, 16);
}

void key_exchange(void) {
    ARRAY(shd, 32);
    ARRAY(key, 32);
    // crypto_key_exchange_public_key is crypto_x25519_public_key
    crypto_key_exchange(shd, key, key);
}

void sign_check(void) {
    ARRAY(hash, 64);
    ARRAY(key,  32);
    ARRAY(pub,  32);
    ARRAY(in,   32);
    crypto_sign_public_key(pub, key);
    crypto_sign(hash, key, pub, in, 32);
    crypto_check(hash, pub, in, 32);
}

void from_eddsa(void) {
    ARRAY(shr, 32);
    ARRAY(key, 32);
    ARRAY(pub, 32);
    crypto_from_eddsa_private(shr, key);
    crypto_sign_public_key(pub, key);
    crypto_from_eddsa_public(shr, pub);
}

void hidden(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    ARRAY(hdn, 32);
    crypto_x25519_public_key(pub, key);
    crypto_curve_to_hidden(hdn, pub, 77);
    crypto_hidden_to_curve(pub, hdn);
    crypto_hidden_key_pair(hdn, key, pub);
}

void hchacha(void) {
    ARRAY(out, 32);
    ARRAY(key, 32);
    ARRAY(in,  16);
    crypto_hchacha20(out, key, in);
}

void chacha(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 8);
    for(size_t i = 0; i < 64; i++)
        crypto_chacha20(out, in, i, key, nonce);
}

void xchacha(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 24);
    for(size_t i = 0; i < 64; i++)
        crypto_xchacha20(out, in, i, key, nonce);
}

void ietf_chacha(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 12);
    for(size_t i = 0; i < 64; i++)
        crypto_ietf_chacha20(out, in, i, key, nonce);
}

void chacha_ctr(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 8);
    for(size_t i = 0; i < 64; i++)
        crypto_chacha20_ctr(out, in, i, key, nonce, 777);
}

void xchacha_ctr(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 24);
    for(size_t i = 0; i < 64; i++)
        crypto_xchacha20_ctr(out, in, i, key, nonce, 777);
}

void ietf_chacha_ctr(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 12);
    for(size_t i = 0; i < 64; i++)
        crypto_ietf_chacha20_ctr(out, in, i, key, nonce, 777);
}

void x25519(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    ARRAY(shr, 32);
    key[0] = 0;
    crypto_x25519_public_key(pub, key);
    crypto_x25519(shr, key, pub);
}

void dirty(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    crypto_x25519_dirty_small(pub, key);
    crypto_x25519_dirty_fast (pub, key);
}

void inverse(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    ARRAY(bld, 32);
    crypto_x25519_public_key(pub, key);
    crypto_x25519_inverse(bld, key, pub);
}

void sha512(void) {
    ARRAY(hash,  64);
    ARRAY(in  , 128);
    for(size_t i = 0; i < 128; i++)
        crypto_sha512(hash, in, i);
}

void hmac(void) {
    ARRAY(hash, 64);
    ARRAY(key , 64);
    ARRAY(in  , 64);
    for(size_t i = 0; i < 64; i++)
        crypto_hmac_sha512(hash, key, 64, in, i);
}

void sign_check_ed25519(void) {
    ARRAY(hash, 64);
    ARRAY(key,  32);
    ARRAY(pub,  32);
    ARRAY(in,   32);
    crypto_ed25519_public_key(pub, key);
    crypto_ed25519_sign(hash, key, pub, in, 32);
    crypto_ed25519_check(hash, pub, in, 32);
}

int main(void) {
    p1305();
    blake2b();
    verify();
    wipe();
    lock_unlock();
    argon();
    key_exchange();
    sign_check();
    from_eddsa();
    hidden();
    hchacha();
    chacha();
    xchacha();
    ietf_chacha();
    chacha_ctr();
    xchacha_ctr();
    ietf_chacha_ctr();
    x25519();
    dirty();
    inverse();
    sha512();
    hmac();
    sign_check_ed25519();
    return 0;
}
