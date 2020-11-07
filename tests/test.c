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
// Copyright (c) 2017-2020, Loup Vaillant and Richard Walmsley
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
// Written in 2017-2020 by Loup Vaillant and Richard Walmsley
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
#include "vectors.h"

#define CHACHA_BLOCK_SIZE    64
#define POLY1305_BLOCK_SIZE  16
#define BLAKE2B_BLOCK_SIZE  128
#define SHA_512_BLOCK_SIZE  128

////////////////////////////
/// Tests aginst vectors ///
////////////////////////////
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
        exit(1);
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
        exit(1);
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
        exit(1);
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

static void x25519(vector_reader *reader)
{
    vector scalar = next_input(reader);
    vector point  = next_input(reader);
    vector out    = next_output(reader);
    crypto_x25519(out.buf, scalar.buf, point.buf);
}

static void x25519_pk(vector_reader *reader)
{
    vector in  = next_input(reader);
    vector out = next_output(reader);
    crypto_x25519_public_key(out.buf, in.buf);
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

static void edDSA_pk(vector_reader *reader)
{
    vector in  = next_input(reader);
    vector out = next_output(reader);
    crypto_sign_public_key(out.buf, in.buf);
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

static void ed_25519_pk(vector_reader *reader)
{
    vector in  = next_input(reader);
    vector out = next_output(reader);
    crypto_ed25519_public_key(out.buf, in.buf);
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

static void iterate_x25519(u8 k[32], u8 u[32])
{
    u8 tmp[32];
    crypto_x25519(tmp , k, u);
    memcpy(u, k  , 32);
    memcpy(k, tmp, 32);
}

static int test_x25519()
{
    u8 _1   [32] = {0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
                    0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
                    0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
                    0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79};
    u8 k[32] = {9};
    u8 u[32] = {9};

    crypto_x25519_public_key(k, u);
    int status = memcmp(k, _1, 32);
    printf("%s: x25519 1\n", status != 0 ? "FAILED" : "OK");

    u8 _1k  [32] = {0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
                    0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
                    0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
                    0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51};
    FOR (i, 1, 1000) { iterate_x25519(k, u); }
    status |= memcmp(k, _1k, 32);
    printf("%s: x25519 1K\n", status != 0 ? "FAILED" : "OK");

    // too long; didn't run
    //u8 _1M[32] = {0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd,
    //              0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f,
    //              0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf,
    //              0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24};
    //FOR (i, 1000, 1000000) { iterate_x25519(k, u); }
    //status |= memcmp(k, _1M, 32);
    //printf("%s: x25519 1M\n", status != 0 ? "FAILED" : "OK");
    return status;
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

//////////////////////////////
/// Self consistency tests ///
//////////////////////////////
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
static int p_verify16(){ return p_verify(16, crypto_verify16); }
static int p_verify32(){ return p_verify(32, crypto_verify32); }
static int p_verify64(){ return p_verify(64, crypto_verify64); }

static int p_chacha20_ctr()
{
    int status = 0;
    RANDOM_INPUT(key  ,  32);
    RANDOM_INPUT(nonce,  24);
    RANDOM_INPUT(plain, 128);
    u8 out_full[128];
    u8 out1     [64];
    u8 out2     [64];
    crypto_chacha20    (out_full, plain     , 128, key, nonce);
    crypto_chacha20_ctr(out1    , plain +  0,  64, key, nonce, 0);
    crypto_chacha20_ctr(out2    , plain + 64,  64, key, nonce, 1);
    status |= memcmp(out_full     , out1, 64);
    status |= memcmp(out_full + 64, out2, 64);

    crypto_ietf_chacha20    (out_full, plain     , 128, key, nonce);
    crypto_ietf_chacha20_ctr(out1    , plain +  0,  64, key, nonce, 0);
    crypto_ietf_chacha20_ctr(out2    , plain + 64,  64, key, nonce, 1);
    status |= memcmp(out_full     , out1, 64);
    status |= memcmp(out_full + 64, out2, 64);

    crypto_xchacha20    (out_full, plain     , 128, key, nonce);
    crypto_xchacha20_ctr(out1    , plain +  0,  64, key, nonce, 0);
    crypto_xchacha20_ctr(out2    , plain + 64,  64, key, nonce, 1);
    status |= memcmp(out_full     , out1, 64);
    status |= memcmp(out_full + 64, out2, 64);

    printf("%s: Chacha20 (ctr)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that Chacha20(nullptr) == Chacha20(all-zeroes)
static int p_chacha20_stream()
{
    int status = 0;
#define INPUT_SIZE (CHACHA_BLOCK_SIZE * 2 + 1)
    FOR (i, 0, INPUT_SIZE) {
        u8 output_normal[INPUT_SIZE];
        u8 output_stream[INPUT_SIZE];
        u8 zeroes       [INPUT_SIZE] = {0};
        RANDOM_INPUT(key  , 32);
        RANDOM_INPUT(nonce, 8);
        crypto_chacha20(output_normal, zeroes, i, key, nonce);
        crypto_chacha20(output_stream, 0     , i, key, nonce);
        status |= memcmp(output_normal, output_stream, i);
    }
    printf("%s: Chacha20 (nullptr == zeroes)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that output and input can be the same pointer
static int p_chacha20_same_ptr()
{
#undef INPUT_SIZE
#define INPUT_SIZE (CHACHA_BLOCK_SIZE * 4) // total input size
    int status = 0;
    u8  output[INPUT_SIZE];
    RANDOM_INPUT(input, INPUT_SIZE);
    RANDOM_INPUT(key  , 32);
    RANDOM_INPUT(nonce, 8);
    crypto_chacha20(output, input, INPUT_SIZE, key, nonce);
    crypto_chacha20(input , input, INPUT_SIZE, key, nonce);
    status |= memcmp(output, input, INPUT_SIZE);
    printf("%s: Chacha20 (output == input)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_hchacha20()
{
    int status = 0;
    FOR (i, 0, 100) {
        RANDOM_INPUT(buffer, 80);
        size_t out_idx = rand64() % 48;
        size_t key_idx = rand64() % 48;
        size_t in_idx  = rand64() % 64;
        u8 key[32]; FOR (j, 0, 32) { key[j] = buffer[j + key_idx]; }
        u8 in [16]; FOR (j, 0, 16) { in [j] = buffer[j +  in_idx]; }

        // Run with and without overlap, then compare
        u8 out[32];
        crypto_hchacha20(out, key, in);
        crypto_hchacha20(buffer + out_idx, buffer + key_idx, buffer + in_idx);
        status |= memcmp(out, buffer + out_idx, 32);
    }
    printf("%s: HChacha20 (overlap)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that authenticating bit by bit yields the same mac than
// authenticating all at once
static int p_poly1305()
{
#undef INPUT_SIZE
#define INPUT_SIZE (POLY1305_BLOCK_SIZE * 4) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 mac_chunk[16];
        u8 mac_whole[16];
        // inputs
        RANDOM_INPUT(input, INPUT_SIZE);
        RANDOM_INPUT(key  , 32);

        // Authenticate bit by bit
        crypto_poly1305_ctx ctx;
        crypto_poly1305_init(&ctx, key);
        crypto_poly1305_update(&ctx, input    , i);
        crypto_poly1305_update(&ctx, input + i, INPUT_SIZE - i);
        crypto_poly1305_final(&ctx, mac_chunk);

        // Authenticate all at once
        crypto_poly1305(mac_whole, input, INPUT_SIZE, key);

        // Compare the results (must be the same)
        status |= memcmp(mac_chunk, mac_whole, 16);
    }
    printf("%s: Poly1305 (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of poly1305 can overlap.
static int p_poly1305_overlap()
{
#undef INPUT_SIZE
#define INPUT_SIZE (POLY1305_BLOCK_SIZE + (2 * 16)) // total input size
    int status = 0;
    FOR (i, 0, POLY1305_BLOCK_SIZE + 16) {
        RANDOM_INPUT(input, INPUT_SIZE);
        RANDOM_INPUT(key  , 32);
        u8 mac  [16];
        crypto_poly1305(mac    , input + 16, POLY1305_BLOCK_SIZE, key);
        crypto_poly1305(input+i, input + 16, POLY1305_BLOCK_SIZE, key);
        status |= memcmp(mac, input + i, 16);
    }
    printf("%s: Poly1305 (overlapping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that hashing bit by bit yields the same hash than hashing all
// at once.  Note: I figured we didn't need to test keyed mode, or
// different hash sizes, again.  This test sticks to the simplified
// interface.
static int p_blake2b()
{
#undef INPUT_SIZE
#define INPUT_SIZE (BLAKE2B_BLOCK_SIZE * 4 - 32) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 hash_chunk[64];
        u8 hash_whole[64];
        // inputs
        RANDOM_INPUT(input, INPUT_SIZE);

        // Authenticate bit by bit
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx);
        crypto_blake2b_update(&ctx, input    , i);
        crypto_blake2b_update(&ctx, input + i, INPUT_SIZE - i);
        crypto_blake2b_final(&ctx, hash_chunk);

        // Authenticate all at once
        crypto_blake2b(hash_whole, input, INPUT_SIZE);

        // Compare the results (must be the same)
        status |= memcmp(hash_chunk, hash_whole, 64);
    }
    printf("%s: Blake2b (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of Blake2b can overlap.
static int p_blake2b_overlap()
{
#undef INPUT_SIZE
#define INPUT_SIZE (BLAKE2B_BLOCK_SIZE + (2 * 64)) // total input size
    int status = 0;
    FOR (i, 0, BLAKE2B_BLOCK_SIZE + 64) {
        u8 hash [64];
        RANDOM_INPUT(input, INPUT_SIZE);
        crypto_blake2b(hash   , input + 64, BLAKE2B_BLOCK_SIZE);
        crypto_blake2b(input+i, input + 64, BLAKE2B_BLOCK_SIZE);
        status |= memcmp(hash, input + i, 64);
    }
    printf("%s: Blake2b (overlapping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that hashing bit by bit yields the same hash than hashing all
// at once. (for sha512)
static int p_sha512()
{
#undef INPUT_SIZE
#define INPUT_SIZE (SHA_512_BLOCK_SIZE * 4 - 32) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 hash_chunk[64];
        u8 hash_whole[64];
        // inputs
        RANDOM_INPUT(input, INPUT_SIZE);

        // Authenticate bit by bit
        crypto_sha512_ctx ctx;
        crypto_sha512_init(&ctx);
        crypto_sha512_update(&ctx, input    , i);
        crypto_sha512_update(&ctx, input + i, INPUT_SIZE - i);
        crypto_sha512_final(&ctx, hash_chunk);

        // Authenticate all at once
        crypto_sha512(hash_whole, input, INPUT_SIZE);

        // Compare the results (must be the same)
        status |= memcmp(hash_chunk, hash_whole, 64);
    }
    printf("%s: Sha512 (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of crypto_sha_512 can overlap.
static int p_sha512_overlap()
{
#undef INPUT_SIZE
#define INPUT_SIZE (SHA_512_BLOCK_SIZE + (2 * 64)) // total input size
    int status = 0;
    FOR (i, 0, SHA_512_BLOCK_SIZE + 64) {
        u8 hash [64];
        RANDOM_INPUT(input, INPUT_SIZE);
        crypto_sha512(hash   , input + 64, SHA_512_BLOCK_SIZE);
        crypto_sha512(input+i, input + 64, SHA_512_BLOCK_SIZE);
        status |= memcmp(hash, input + i, 64);
    }
    printf("%s: Sha512 (overlapping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that hashing bit by bit yields the same hash than hashing all
// at once. (for hmac)
static int p_hmac_sha512()
{
#undef INPUT_SIZE
#define INPUT_SIZE (SHA_512_BLOCK_SIZE * 4 - 32) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 hash_chunk[64];
        u8 hash_whole[64];
        // inputs
        RANDOM_INPUT(key  , 32);
        RANDOM_INPUT(input, INPUT_SIZE);

        // Authenticate bit by bit
        crypto_hmac_sha512_ctx ctx;
        crypto_hmac_sha512_init(&ctx, key, 32);
        crypto_hmac_sha512_update(&ctx, input    , i);
        crypto_hmac_sha512_update(&ctx, input + i, INPUT_SIZE - i);
        crypto_hmac_sha512_final(&ctx, hash_chunk);

        // Authenticate all at once
        crypto_hmac_sha512(hash_whole, key, 32, input, INPUT_SIZE);

        // Compare the results (must be the same)
        status |= memcmp(hash_chunk, hash_whole, 64);
    }
    printf("%s: HMAC SHA-512 (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of crypto_sha_512 can overlap.
static int p_hmac_sha512_overlap()
{
#undef INPUT_SIZE
#define INPUT_SIZE (SHA_512_BLOCK_SIZE + (2 * 64)) // total input size
    int status = 0;
    FOR (i, 0, SHA_512_BLOCK_SIZE + 64) {
        u8 hash [64];
        RANDOM_INPUT(key  , 32);
        RANDOM_INPUT(input, INPUT_SIZE);
        crypto_hmac_sha512(hash   , key, 32, input + 64, SHA_512_BLOCK_SIZE);
        crypto_hmac_sha512(input+i, key, 32, input + 64, SHA_512_BLOCK_SIZE);
        status |= memcmp(hash, input + i, 64);
    }
    printf("%s: HMAC SHA-512 (overlapping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_argon2i_easy()
{
    int   status    = 0;
    void *work_area = alloc(8 * 1024);
    RANDOM_INPUT(password , 32);
    RANDOM_INPUT(salt     , 16);
    u8 hash_general[32];
    u8 hash_easy   [32];
    crypto_argon2i_general(hash_general, 32, work_area, 8, 1,
                           password, 32, salt, 16, 0, 0, 0, 0);
    crypto_argon2i(hash_easy, 32, work_area, 8, 1, password, 32, salt, 16);
    status |= memcmp(hash_general, hash_easy, 32);
    free(work_area);
    printf("%s: Argon2i (easy interface)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_argon2i_overlap()
{
    int status          = 0;
    u8 *work_area       = (u8*)alloc(8 * 1024);
    u8 *clean_work_area = (u8*)alloc(8 * 1024);
    FOR (i, 0, 10) {
        p_random(work_area, 8 * 1024);
        u32 hash_offset = rand64() % 64;
        u32 pass_offset = rand64() % 64;
        u32 salt_offset = rand64() % 64;
        u32 key_offset  = rand64() % 64;
        u32 ad_offset   = rand64() % 64;
        u8  hash1[32];
        u8 *hash2 = work_area + hash_offset;
        u8  pass [16];  FOR (j, 0, 16) { pass[j] = work_area[j + pass_offset]; }
        u8  salt [16];  FOR (j, 0, 16) { salt[j] = work_area[j + salt_offset]; }
        u8  key  [32];  FOR (j, 0, 32) { key [j] = work_area[j +  key_offset]; }
        u8  ad   [32];  FOR (j, 0, 32) { ad  [j] = work_area[j +   ad_offset]; }

        crypto_argon2i_general(hash1, 32, clean_work_area, 8, 1,
                               pass, 16, salt, 16, key, 32, ad, 32);
        crypto_argon2i_general(hash2, 32, work_area, 8, 1,
                               work_area + pass_offset, 16,
                               work_area + salt_offset, 16,
                               work_area +  key_offset, 32,
                               work_area +   ad_offset, 32);
        status |= memcmp(hash1, hash2, 32);
    }
    free(work_area);
    free(clean_work_area);
    printf("%s: Argon2i (overlapping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the shared key and secret key buffers of crypto_x25519 can
// overlap.
static int p_x25519_overlap()
{
    int status = 0;
    FOR (i, 0, 62) {
        u8 overlapping[94];
        u8 separate[32];
        RANDOM_INPUT(sk, 32);
        RANDOM_INPUT(pk, 32);
        memcpy(overlapping + 31, sk, 32);
        crypto_x25519(overlapping + i, overlapping + 31, pk);
        crypto_x25519(separate, sk, pk);
        status |= memcmp(separate, overlapping + i, 32);
    }
    printf("%s: x25519 (overlapping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the shared key and secret key buffers of
// crypto_key_exchange can overlap.
static int p_key_exchange_overlap()
{
    int status = 0;
    FOR (i, 0, 62) {
        u8 overlapping[94];
        u8 separate[32];
        RANDOM_INPUT(sk, 32);
        RANDOM_INPUT(pk, 32);
        memcpy(overlapping + 31, sk, 32);
        crypto_key_exchange(overlapping + i, overlapping + 31, pk);
        crypto_key_exchange(separate, sk, pk);
        status |= memcmp(separate, overlapping + i, 32);
    }
    printf("%s: key_exchange (overlapping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_eddsa_roundtrip()
{
#define MESSAGE_SIZE 30
    int status = 0;
    FOR (i, 0, MESSAGE_SIZE) {
        RANDOM_INPUT(message, MESSAGE_SIZE);
        RANDOM_INPUT(sk, 32);
        u8 pk       [32]; crypto_sign_public_key(pk, sk);
        u8 signature[64]; crypto_sign(signature, sk, pk, message, i);
        status |= crypto_check(signature, pk, message, i);

        // reject forgeries
        u8 zero   [64] = {0};
        u8 forgery[64]; FOR (j, 0, 64) { forgery[j] = signature[j] + 1; }
        status |= !crypto_check(zero   , pk, message, i);
        status |= !crypto_check(forgery, pk, message, i);
    }
    printf("%s: EdDSA (roundtrip)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Verifies that random signatures are all invalid.  Uses random
// public keys to see what happens outside of the curve (it should
// yield an invalid signature).
static int p_eddsa_random()
{
    int status = 0;
    FOR (i, 0, 100) {
        RANDOM_INPUT(message, MESSAGE_SIZE);
        RANDOM_INPUT(pk, 32);
        RANDOM_INPUT(signature , 64);
        status |= ~crypto_check(signature, pk, message, MESSAGE_SIZE);
    }
    // Testing S == L (for code coverage)
    RANDOM_INPUT(message, MESSAGE_SIZE);
    RANDOM_INPUT(pk, 32);
    static const u8 signature[64] =
        { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
          0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
    status |= ~crypto_check(signature, pk, message, MESSAGE_SIZE);

    printf("%s: EdDSA (random)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of crypto_sign() can overlap.
static int p_eddsa_overlap()
{
    int status = 0;
    FOR(i, 0, MESSAGE_SIZE + 64) {
#undef INPUT_SIZE
#define INPUT_SIZE (MESSAGE_SIZE + (2 * 64)) // total input size
        RANDOM_INPUT(input, INPUT_SIZE);
        RANDOM_INPUT(sk   , 32        );
        u8 pk       [32];  crypto_sign_public_key(pk, sk);
        u8 signature[64];
        crypto_sign(signature, sk, pk, input + 64, MESSAGE_SIZE);
        crypto_sign(input+i  , sk, pk, input + 64, MESSAGE_SIZE);
        status |= memcmp(signature, input + i, 64);
    }
    printf("%s: EdDSA (overlap)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_eddsa_incremental()
{
    int status = 0;
    FOR (i, 0, MESSAGE_SIZE) {
        RANDOM_INPUT(msg, MESSAGE_SIZE);
        RANDOM_INPUT(sk, 32);
        u8 pk      [32];  crypto_sign_public_key(pk, sk);
        u8 sig_mono[64];  crypto_sign(sig_mono, sk, pk, msg, MESSAGE_SIZE);
        u8 sig_incr[64];
        {
            crypto_sign_ctx ctx;
            crypto_sign_ctx_abstract *actx = (crypto_sign_ctx_abstract*)&ctx;
            crypto_sign_init_first_pass (actx, sk, pk);
            crypto_sign_update          (actx, msg  , i);
            crypto_sign_update          (actx, msg+i, MESSAGE_SIZE-i);
            crypto_sign_init_second_pass(actx);
            crypto_sign_update          (actx, msg  , i);
            crypto_sign_update          (actx, msg+i, MESSAGE_SIZE-i);
            crypto_sign_final           (actx, sig_incr);
        }
        status |= memcmp(sig_mono, sig_incr, 64);
        status |= crypto_check(sig_mono, pk, msg, MESSAGE_SIZE);
        {
            crypto_check_ctx ctx;
            crypto_check_ctx_abstract *actx = (crypto_check_ctx_abstract*)&ctx;
            crypto_check_init  (actx, sig_incr, pk);
            crypto_check_update(actx, msg  , i);
            crypto_check_update(actx, msg+i, MESSAGE_SIZE-i);
            status |= crypto_check_final(actx);
        }
    }
    printf("%s: EdDSA (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_aead()
{
    int status = 0;
    FOR (i, 0, 1000) {
        RANDOM_INPUT(key      , 32);
        RANDOM_INPUT(nonce    , 24);
        RANDOM_INPUT(ad       ,  4);
        RANDOM_INPUT(plaintext,  8);
        u8 box[24], box2[24];
        u8 out[8];
        // AEAD roundtrip
        crypto_lock_aead(box, box+16, key, nonce, ad, 4, plaintext, 8);
        status |= crypto_unlock_aead(out, key, nonce, box, ad, 4, box+16, 8);
        status |= memcmp(plaintext, out, 8);
        box[0]++;
        status |= !crypto_unlock_aead(out, key, nonce, box, ad, 4, box+16, 8);

        // Authenticated roundtrip (easy interface)
        // Make and accept message
        crypto_lock(box, box + 16, key, nonce, plaintext, 8);
        status |= crypto_unlock(out, key, nonce, box, box + 16, 8);
        // Make sure decrypted text and original text are the same
        status |= memcmp(plaintext, out, 8);
        // Make and reject forgery
        box[0]++;
        status |= !crypto_unlock(out, key, nonce, box, box + 16, 8);
        box[0]--; // undo forgery

        // Same result for both interfaces
        crypto_lock_aead(box2, box2 + 16, key, nonce, 0, 0, plaintext, 8);
        status |= memcmp(box, box2, 24);
    }
    printf("%s: aead (roundtrip)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Elligator direct mapping must ignore the most significant bits
static int p_elligator_direct_msb()
{
    int status = 0;
    FOR (i, 0, 20) {
        RANDOM_INPUT(r, 32);
        u8 r1[32];  memcpy(r1, r, 32);  r1[31] = (r[31] & 0x3f) | 0x00;
        u8 r2[32];  memcpy(r2, r, 32);  r2[31] = (r[31] & 0x3f) | 0x40;
        u8 r3[32];  memcpy(r3, r, 32);  r3[31] = (r[31] & 0x3f) | 0x80;
        u8 r4[32];  memcpy(r4, r, 32);  r4[31] = (r[31] & 0x3f) | 0xc0;
        u8 u [32];  crypto_hidden_to_curve(u , r );
        u8 u1[32];  crypto_hidden_to_curve(u1, r1);
        u8 u2[32];  crypto_hidden_to_curve(u2, r2);
        u8 u3[32];  crypto_hidden_to_curve(u3, r3);
        u8 u4[32];  crypto_hidden_to_curve(u4, r4);
        status |= memcmp(u, u1, 32);
        status |= memcmp(u, u2, 32);
        status |= memcmp(u, u3, 32);
        status |= memcmp(u, u4, 32);
    }
    printf("%s: elligator direct (msb)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_elligator_direct_overlap()
{
    int status = 0;
    FOR (i, 0, 62) {
        u8 overlapping[94];
        u8 separate[32];
        RANDOM_INPUT(r, 32);
        memcpy(overlapping + 31, r, 32);
        crypto_hidden_to_curve(overlapping + i, overlapping + 31);
        crypto_hidden_to_curve(separate, r);
        status |= memcmp(separate, overlapping + i, 32);
    }
    printf("%s: elligator direct (overlapping i/o)\n",
           status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_elligator_inverse_overlap()
{
    int status = 0;
    FOR (i, 0, 62) {
        u8 overlapping[94];
        u8 separate[32];
        RANDOM_INPUT(pk, 33);
        u8 tweak = pk[32];
        memcpy(overlapping + 31, pk, 32);
        int a = crypto_curve_to_hidden(overlapping+i, overlapping+31, tweak);
        int b = crypto_curve_to_hidden(separate, pk, tweak);
        status |= a - b;
        if (a == 0) {
            // The buffers are the same only if written to to begin with
            status |= memcmp(separate, overlapping + i, 32);
        }
    }
    printf("%s: elligator inverse (overlapping i/o)\n",
           status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_elligator_x25519()
{
    int status = 0;
    int i = 0;
    while (i < 64) {
        RANDOM_INPUT(sk1, 32);
        RANDOM_INPUT(sk2, 32);
        u8 skc [32];  memcpy(skc, sk1, 32);  skc[0] &= 248;
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

        // Dirty functions behave the same as the clean one if the lsb
        // are 0, differently if it is not
        if ((sk1[0] & 7) == 0) { status |= memcmp(pk1, pkf, 32);      }
        else                   { status |= memcmp(pk1, pkf, 32) == 0; }

        // Maximise tweak diversity.
        // We want to set the bits 1 (sign) and 6-7 (padding)
        u8 tweak = (u8)((i & 1) + (i << 5));
        u8 r[32];
        if (crypto_curve_to_hidden(r, pkf, tweak)) {
            continue; // retry untill success (doesn't increment the tweak)
        }
        // Verify that the tweak's msb are copied to the representative
        status |= (tweak >> 6) ^ (r[31] >> 6);

        // Round trip
        u8 pkr[32];  crypto_hidden_to_curve(pkr, r);
        status |= memcmp(pkr, pkf, 32);

        // Dirty and safe keys are compatible
        u8 e1 [32];  crypto_x25519(e1, sk2, pk1);
        u8 e2 [32];  crypto_x25519(e2, sk2, pkr);
        status |= memcmp(e1, e2, 32);
        i++;
    }
    printf("%s: elligator x25519\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_elligator_key_pair()
{
    int status = 0;
    FOR(i, 0, 32) {
        RANDOM_INPUT(seed, 32);
        RANDOM_INPUT(sk2 , 32);
        u8 r  [32];
        u8 sk1[32];  crypto_hidden_key_pair(r, sk1, seed);
        u8 pkr[32];  crypto_hidden_to_curve(pkr, r);
        u8 pk1[32];  crypto_x25519_public_key(pk1, sk1);
        u8 e1 [32];  crypto_x25519(e1, sk2, pk1);
        u8 e2 [32];  crypto_x25519(e2, sk2, pkr);
        status |= memcmp(e1, e2, 32);
    }

    printf("%s: elligator key pair\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_elligator_key_pair_overlap()
{
    int status = 0;
    FOR (i, 0, 94) {
        u8 over[158];
        u8 sep [ 64];
        RANDOM_INPUT(s1, 32);
        u8 *s2 = over + 63;
        memcpy(s2, s1, 32);
        crypto_hidden_key_pair(sep     , sep      + 32, s1);
        crypto_hidden_key_pair(over + i, over + i + 32, s2);
        status |= memcmp(sep, over + i, 64);
    }

    printf("%s: elligator key pair (overlapping i/o)\n",
           status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_x25519_inverse()
{
    int status = 0;
    RANDOM_INPUT(b, 32);
    u8 base[32];  // random point (cofactor is cleared).
    crypto_x25519_public_key(base, b);
    // check round trip
    FOR (i, 0, 50) {
        RANDOM_INPUT(sk, 32);
        u8 pk   [32];
        u8 blind[32];
        crypto_x25519(pk, sk, base);
        crypto_x25519_inverse(blind, sk, pk);
        status |= memcmp(blind, base, 32);
    }

    // check cofactor clearing
    // (Multiplying by a low order point yields zero
    u8 low_order[4][32] = {
        {0}, {1},
        {0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
         0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
         0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
         0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,},
        {0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
         0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
         0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
         0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,},
    };
    u8 zero[32] = {0};
    FOR (i, 0, 32) {
        u8 blind[32];
        RANDOM_INPUT(sk, 32);
        crypto_x25519_inverse(blind, sk, low_order[i%4]);
        status |= memcmp(blind, zero, 32);
    }
    printf("%s: x25519_inverse\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_x25519_inverse_overlap()
{
    int status = 0;
    FOR (i, 0, 62) {
        u8 overlapping[94];
        u8 separate[32];
        RANDOM_INPUT(sk, 32);
        RANDOM_INPUT(pk, 32);
        memcpy(overlapping + 31, sk, 32);
        crypto_x25519_inverse(overlapping + i, overlapping + 31, pk);
        crypto_x25519_inverse(separate, sk, pk);
        status |= memcmp(separate, overlapping + i, 32);
    }
    printf("%s: x25519 inverse (overlapping i/o)\n",
           status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_from_eddsa()
{
    int status = 0;
    FOR (i, 0, 32) {
        RANDOM_INPUT(ed_private, 32);
        u8 ed_public[32];  crypto_sign_public_key   (ed_public, ed_private);
        u8 x_private[32];  crypto_from_eddsa_private(x_private, ed_private);
        u8 x_public1[32];  crypto_from_eddsa_public (x_public1, ed_public);
        u8 x_public2[32];  crypto_x25519_public_key (x_public2, x_private);
        status |= memcmp(x_public1, x_public2, 32);
    }
    printf("%s: from_eddsa\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_from_ed25519()
{
    int status = 0;
    FOR (i, 0, 32) {
        RANDOM_INPUT(ed_private, 32);
        u8 ed_public[32];  crypto_ed25519_public_key  (ed_public, ed_private);
        u8 x_private[32];  crypto_from_ed25519_private(x_private, ed_private);
        u8 x_public1[32];  crypto_from_ed25519_public (x_public1, ed_public);
        u8 x_public2[32];  crypto_x25519_public_key   (x_public2, x_private);
        status |= memcmp(x_public1, x_public2, 32);
    }
    printf("%s: from_ed25519\n", status != 0 ? "FAILED" : "OK");
    return status;
}

int vector_test(void (*f)(vector_reader*),
                const char *name, size_t nb_vectors, const char *vectors[]);

#define TEST(name) vector_test(name, #name, nb_##name##_vectors, name##_vectors)

int main(int argc, char *argv[])
{
    if (argc > 1) {
        sscanf(argv[1], "%" PRIu64 "", &random_state);
    }
    printf("\nRandom seed: %" PRIu64 "\n", random_state);

    int status = 0;
    printf("\nTest against vectors");
    printf("\n--------------------\n");
    status |= TEST(chacha20);
    status |= TEST(ietf_chacha20);
    status |= TEST(hchacha20);
    status |= TEST(xchacha20);
    status |= TEST(poly1305);
    status |= TEST(aead_ietf);
    status |= TEST(blake2b);
    status |= TEST(sha512);
    status |= TEST(hmac_sha512);
    status |= TEST(argon2i);
    status |= TEST(x25519);
    status |= TEST(x25519_pk);
    status |= TEST(key_exchange);
    status |= TEST(edDSA);
    status |= TEST(edDSA_pk);
    status |= TEST(ed_25519);
    status |= TEST(ed_25519_pk);
    status |= TEST(ed_25519_check);
    status |= TEST(elligator_dir);
    status |= TEST(elligator_inv);
    status |= test_x25519();
    printf("\nProperty based tests");
    printf("\n--------------------\n");
    status |= p_verify16();
    status |= p_verify32();
    status |= p_verify64();
    status |= p_chacha20_ctr();
    status |= p_chacha20_stream();
    status |= p_chacha20_same_ptr();
    status |= p_hchacha20();
    status |= p_poly1305();
    status |= p_poly1305_overlap();
    status |= p_blake2b();
    status |= p_blake2b_overlap();
    status |= p_sha512();
    status |= p_sha512_overlap();
    status |= p_hmac_sha512();
    status |= p_hmac_sha512_overlap();
    status |= p_argon2i_easy();
    status |= p_argon2i_overlap();
    status |= p_x25519_overlap();
    status |= p_key_exchange_overlap();
    status |= p_eddsa_roundtrip();
    status |= p_eddsa_random();
    status |= p_eddsa_overlap();
    status |= p_eddsa_incremental();
    status |= p_aead();
    status |= p_elligator_direct_msb();
    status |= p_elligator_direct_overlap();
    status |= p_elligator_inverse_overlap();
    status |= p_elligator_x25519();
    status |= p_elligator_key_pair();
    status |= p_elligator_key_pair_overlap();
    status |= p_x25519_inverse();
    status |= p_x25519_inverse_overlap();
    status |= p_from_eddsa();
    status |= p_from_ed25519();
    printf("\n%s\n\n", status != 0 ? "SOME TESTS FAILED" : "All tests OK!");
    return status;
}
