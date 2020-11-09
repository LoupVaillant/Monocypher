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
// Copyright (c) 2020, Mike Pechkin and Loup Vaillant
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
// Written in 2017-2020 by Mike Pechkin and Loup Vaillant
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
#include "utils.h"
#include "tis-ci-vectors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY(name, size)                               \
    u8 name[size];                                      \
    for(size_t i = 0; i < size; i++) name[i] = i;

static void chacha20(vector_reader *reader)
{
    vector key       = next_input(reader);
    vector nonce     = next_input(reader);
    vector plain     = next_input(reader);
    u64    ctr       = load64_le(next_input(reader).buf);
    vector out       = next_output(reader);
    u64    nb_blocks = plain.size / 64 + (plain.size % 64 != 0);
    u64    new_ctr   = crypto_chacha20_ctr(out.buf, plain.buf, plain.size,
                                            key.buf, nonce.buf, ctr);
    if (new_ctr - ctr != nb_blocks) {
        printf("FAILURE: Chacha20 returned counter not correct: ");
    }
}

static void ietf_chacha20(vector_reader *reader)
{
    vector key       = next_input(reader);
    vector nonce     = next_input(reader);
    vector plain     = next_input(reader);
    u64    ctr       = load64_le(next_input(reader).buf);
    vector out       = next_output(reader);
    u32    nb_blocks = (u32)(plain.size / 64 + (plain.size % 64 != 0));
    u32    new_ctr   = crypto_ietf_chacha20_ctr(out.buf, plain.buf, plain.size,
                                                 key.buf, nonce.buf, ctr);
    if (new_ctr - ctr != nb_blocks) {
        printf("FAILURE: IETF Chacha20 returned counter not correct: ");
    }
}

static void hchacha20(vector_reader *reader)
{
    vector key   = next_input(reader);
    vector nonce = next_input(reader);
    vector out   = next_output(reader);
    crypto_hchacha20(out.buf, key.buf, nonce.buf);
}

static void xchacha20(vector_reader *reader)
{
    vector key       = next_input(reader);
    vector nonce     = next_input(reader);
    vector plain     = next_input(reader);
    u64    ctr       = load64_le(next_input(reader).buf);
    vector out       = next_output(reader);
    u64    nb_blocks = plain.size / 64 + (plain.size % 64 != 0);
    u64    new_ctr   = crypto_xchacha20_ctr(out.buf, plain.buf, plain.size,
                                             key.buf, nonce.buf, ctr);
    if (new_ctr - ctr != nb_blocks) {
        printf("FAILURE: XChacha20 returned counter not correct: ");
    }
}

static void poly1305(vector_reader *reader)
{
    vector key = next_input(reader);
    vector msg = next_input(reader);
    vector out = next_output(reader);
    crypto_poly1305(out.buf, msg.buf, msg.size, key.buf);
}

static void aead_ietf(vector_reader *reader)
{
    vector key   = next_input(reader);
    vector nonce = next_input(reader);
    vector ad    = next_input(reader);
    vector text  = next_input(reader);
    vector out   = next_output(reader);
    crypto_lock_aead(out.buf, out.buf + 16, key.buf, nonce.buf,
                     ad.buf, ad.size, text.buf, text.size);
}

static void blake2b(vector_reader *reader)
{
    vector msg = next_input(reader);
    vector key = next_input(reader);
    vector out = next_output(reader);
    crypto_blake2b_general(out.buf, out.size,
                           key.buf, key.size,
                           msg.buf, msg.size);
}

static void sha512(vector_reader *reader)
{
    vector in  = next_input(reader);
    vector out = next_output(reader);
    crypto_sha512(out.buf, in.buf, in.size);
}

static void hmac_sha512(vector_reader *reader)
{
    vector key = next_input(reader);
    vector msg = next_input(reader);
    vector out = next_output(reader);
    crypto_hmac_sha512(out.buf, key.buf, key.size, msg.buf, msg.size);
}

static void argon2i(vector_reader *reader)
{
    u64    nb_blocks     = load64_le(next_input(reader).buf);
    u64    nb_iterations = load64_le(next_input(reader).buf);
    vector password      = next_input(reader);
    vector salt          = next_input(reader);
    vector key           = next_input(reader);
    vector ad            = next_input(reader);
    vector out           = next_output(reader);
    void  *work_area     = alloc(nb_blocks * 1024);
    crypto_argon2i_general(out.buf, (u32)out.size,
                           work_area, (u32)nb_blocks, (u32)nb_iterations,
                           password.buf, (u32)password.size,
                           salt    .buf, (u32)salt    .size,
                           key     .buf, (u32)key     .size,
                           ad      .buf, (u32)ad      .size);
    free(work_area);
}

static void key_exchange(vector_reader *reader)
{
    vector secret_key = next_input(reader);
    vector public_key = next_input(reader);
    vector out        = next_output(reader);
    crypto_key_exchange(out.buf, secret_key.buf, public_key.buf);
}

static void edDSA(vector_reader *reader)
{
    vector secret_k = next_input(reader);
    vector public_k = next_input(reader);
    vector msg      = next_input(reader);
    vector out      = next_output(reader);
    u8     out2[64];

    // Sign with cached public key, then by reconstructing the key
    crypto_sign(out.buf, secret_k.buf, public_k.buf, msg.buf, msg.size);
    crypto_sign(out2   , secret_k.buf, 0           , msg.buf, msg.size);
    // Compare signatures (must be the same)
    if (memcmp(out.buf, out2, out.size)) {
        printf("FAILURE: reconstructing public key"
               " yields different signature\n");
        exit(1);
    }
}

static void ed_25519(vector_reader *reader)
{
    vector secret_k = next_input(reader);
    vector public_k = next_input(reader);
    vector msg      = next_input(reader);
    vector out      = next_output(reader);
    u8     out2[64];

    // Sign with cached public key, then by reconstructing the key
    crypto_ed25519_sign(out.buf, secret_k.buf, public_k.buf, msg.buf, msg.size);
    crypto_ed25519_sign(out2   , secret_k.buf, 0           , msg.buf, msg.size);
    // Compare signatures (must be the same)
    if (memcmp(out.buf, out2, out.size)) {
        printf("FAILURE: reconstructing public key"
               " yields different signature\n");
        exit(1);
    }
}

static void ed_25519_check(vector_reader *reader)
{
    vector public_k = next_input(reader);
    vector msg      = next_input(reader);
    vector sig      = next_input(reader);
    vector out      = next_output(reader);
    out.buf[0] = (u8)crypto_ed25519_check(sig.buf, public_k.buf,
                                           msg.buf, msg.size);
}

static void elligator_dir(vector_reader *reader)
{
    vector in  = next_input(reader);
    vector out = next_output(reader);
    crypto_hidden_to_curve(out.buf, in.buf);
}

static void elligator_inv(vector_reader *reader)
{
    vector point   = next_input(reader);
    u8     tweak   = next_input(reader).buf[0];
    u8     failure = next_input(reader).buf[0];
    vector out     = next_output(reader);
    int    check   = crypto_curve_to_hidden(out.buf, point.buf, tweak);
    if ((u8)check != failure) {
        printf("Elligator inverse map: failure mismatch\n");
        exit(1);
    }
    if (check) {
        out.buf[0] = 0;
    }
}

//@ ensures \result == 0;
static int p_from_eddsa()
{
    int status = 0;
    RANDOM_INPUT(ed_private, 32);
    u8 ed_public[32];  crypto_sign_public_key   (ed_public, ed_private);
    u8 x_private[32];  crypto_from_eddsa_private(x_private, ed_private);
    u8 x_public1[32];  crypto_from_eddsa_public (x_public1, ed_public);
    u8 x_public2[32];  crypto_x25519_public_key (x_public2, x_private);
    status |= memcmp(x_public1, x_public2, 32);
    printf("%s: from_eddsa\n", status != 0 ? "FAILED" : "OK");
    return status;
}

//@ ensures \result == 0;
static int p_from_ed25519()
{
    int status = 0;
    RANDOM_INPUT(ed_private, 32);
    u8 ed_public[32];  crypto_ed25519_public_key  (ed_public, ed_private);
    u8 x_private[32];  crypto_from_ed25519_private(x_private, ed_private);
    u8 x_public1[32];  crypto_from_ed25519_public (x_public1, ed_public);
    u8 x_public2[32];  crypto_x25519_public_key   (x_public2, x_private);
    status |= memcmp(x_public1, x_public2, 32);
    printf("%s: from_ed25519\n", status != 0 ? "FAILED" : "OK");
    return status;
}

//@ ensures \result == 0;
static int p_dirty()
{
    int status = 0;

    RANDOM_INPUT(sk1, 32);               sk1[0] |= 1;   // make sure it's dirty
    u8 skc [32];  memcpy(skc, sk1, 32);  skc[0] &= 248; // make sure it's clean
    u8 pks [32];  crypto_x25519_dirty_small(pks , sk1);
    u8 pksc[32];  crypto_x25519_dirty_small(pksc, skc);
    u8 pkf [32];  crypto_x25519_dirty_fast (pkf , sk1);
    u8 pkfc[32];  crypto_x25519_dirty_fast (pkfc, skc);
    u8 pk1 [32];  crypto_x25519_public_key (pk1 , sk1);

    // Both dirty functions behave the same
    status |= memcmp(pks, pkf, 32);

    // Dirty functions behave cleanly if we clear the 3 msb first
    status |= memcmp(pksc, pk1, 32);
    status |= memcmp(pkfc, pk1, 32);

    printf("%s: x25519 dirty\n", status != 0 ? "FAILED" : "OK");
    return status;
}

//@ ensures \result == 0;
static int p_x25519_inverse()
{
    int status = 0;
    RANDOM_INPUT(b, 32);
    u8 base[32];  // random point (cofactor is cleared).
    crypto_x25519_public_key(base, b);
    // check round trip
    RANDOM_INPUT(sk, 32);
    u8 pk   [32];
    u8 blind[32];
    crypto_x25519(pk, sk, base);
    crypto_x25519_inverse(blind, sk, pk);
    status |= memcmp(blind, base, 32);

    // check cofactor clearing
    // (Multiplying by a low order point yields zero
    u8 low_order[32] = {
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
        0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
        0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
        0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
    };
    u8 zero[32] = {0};
    crypto_x25519_inverse(blind, sk, low_order);
    status |= memcmp(blind, zero, 32);
    printf("%s: x25519_inverse\n", status != 0 ? "FAILED" : "OK");
    return status;
}

//@ ensures \result == 0;
static int p_verify(size_t size, int (*compare)(const u8*, const u8*))
{
    int status = 0;
    u8 a[64]; // size <= 64
    u8 b[64]; // size <= 64
    FOR (i, 0, 2) {
        FOR (j, 0, 2) {
            // Set every byte to the chosen value, then compare
            FOR (k, 0, size) {
                a[k] = (u8)i;
                b[k] = (u8)j;
            }
            int cmp = compare(a, b);
            status |= (i == j ? cmp : ~cmp);
            // Set only two bytes to the chosen value, then compare
            FOR (k, 0, size / 2) {
                FOR (l, 0, size) {
                    a[l] = 0;
                    b[l] = 0;
                }
                a[k] = (u8)i; a[k + size/2 - 1] = (u8)i;
                b[k] = (u8)j; b[k + size/2 - 1] = (u8)j;
                cmp = compare(a, b);
                status |= (i == j ? cmp : ~cmp);
            }
        }
    }
    printf("%s: crypto_verify%zu\n", status != 0 ? "FAILED" : "OK", size);
    return status;
}
//@ ensures \result == 0;
static int p_verify16(){ return p_verify(16, crypto_verify16); }
//@ ensures \result == 0;
static int p_verify32(){ return p_verify(32, crypto_verify32); }
//@ ensures \result == 0;
static int p_verify64(){ return p_verify(64, crypto_verify64); }

#define TEST(name)                                                      \
    int v_##name() {                                                    \
        return vector_test(name, #name, nb_##name##_vectors, name##_vectors); \
    }

//@ ensures \result == 0;
TEST(chacha20)
//@ ensures \result == 0;
TEST(ietf_chacha20)
//@ ensures \result == 0;
TEST(hchacha20)
//@ ensures \result == 0;
TEST(xchacha20)
//@ ensures \result == 0;
TEST(poly1305)
//@ ensures \result == 0;
TEST(aead_ietf)
//@ ensures \result == 0;
TEST(blake2b)
//@ ensures \result == 0;
TEST(sha512)
//@ ensures \result == 0;
TEST(hmac_sha512)
//@ ensures \result == 0;
TEST(argon2i)
//@ ensures \result == 0;
TEST(key_exchange)
//@ ensures \result == 0;
TEST(edDSA)
//@ ensures \result == 0;
TEST(ed_25519)
//@ ensures \result == 0;
TEST(ed_25519_check)
//@ ensures \result == 0;
TEST(elligator_dir)
//@ ensures \result == 0;
TEST(elligator_inv)

//@ ensures \result == 0;
int main(void) {
    int status = 0;
    status |= v_chacha20      ();
    status |= v_ietf_chacha20 ();
    status |= v_hchacha20     ();
    status |= v_xchacha20     ();
    status |= v_poly1305      ();
    status |= v_aead_ietf     ();
    status |= v_blake2b       ();
    status |= v_sha512        ();
    status |= v_hmac_sha512   ();
    status |= v_argon2i       ();
    status |= v_key_exchange  ();
    status |= v_edDSA         ();
    status |= v_ed_25519      ();
    status |= v_ed_25519_check();
    status |= v_elligator_dir ();
    status |= v_elligator_inv ();

    status |= p_from_eddsa    ();
    status |= p_from_ed25519  ();
    status |= p_dirty         ();
    status |= p_x25519_inverse();
    status |= p_verify16      ();
    status |= p_verify32      ();
    status |= p_verify64      ();
    return status;
}
