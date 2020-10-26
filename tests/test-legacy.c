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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "deprecated/chacha20.h"
#include "deprecated/aead-incr.h"
#include "utils.h"
#include "vectors.h"

#define CHACHA_BLOCK_SIZE    64
#define CHACHA_NB_BLOCKS     10
#define POLY1305_BLOCK_SIZE  16
#define BLAKE2B_BLOCK_SIZE  128
#define SHA_512_BLOCK_SIZE  128

////////////////////////////
/// Tests aginst vectors ///
////////////////////////////
static void chacha20(vector_reader *reader)
{
    vector key   = next_input(reader);
    vector nonce = next_input(reader);
    vector plain = next_input(reader);
    u64    ctr   = load64_le(next_input(reader).buf);
    vector out   = next_output(reader);

    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key.buf, nonce.buf);
    crypto_chacha20_set_ctr(&ctx, ctr);
    crypto_chacha20_encrypt(&ctx, out.buf, plain.buf, plain.size);
}

static void hchacha20(vector_reader *reader)
{
    vector key   = next_input(reader);
    vector nonce = next_input(reader);
    vector out   = next_output(reader);
    crypto_chacha20_H(out.buf, key.buf, nonce.buf);
}

static void xchacha20(vector_reader *reader)
{
    vector key   = next_input(reader);
    vector nonce = next_input(reader);
    vector plain = next_input(reader);
    u64    ctr   = load64_le(next_input(reader).buf);
    vector out   = next_output(reader);
    crypto_chacha_ctx ctx;
    crypto_chacha20_x_init (&ctx, key.buf, nonce.buf);
    crypto_chacha20_set_ctr(&ctx, ctr);
    crypto_chacha20_encrypt(&ctx, out.buf, plain.buf, plain.size);
}

//////////////////////////////
/// Self consistency tests ///
//////////////////////////////

// Tests that encrypting in chunks yields the same result than
// encrypting all at once.
static int p_chacha20()
{
#undef INPUT_SIZE
#define INPUT_SIZE (CHACHA_BLOCK_SIZE * 4) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 output_chunk[INPUT_SIZE];
        u8 output_whole[INPUT_SIZE];
        // inputs
        RANDOM_INPUT(input, INPUT_SIZE);
        RANDOM_INPUT(key  , 32);
        RANDOM_INPUT(nonce, 8);

        // Encrypt in chunks
        crypto_chacha_ctx ctx;
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_encrypt(&ctx, output_chunk  , input  , i);
        crypto_chacha20_encrypt(&ctx, output_chunk+i, input+i, INPUT_SIZE-i);
        // Encrypt all at once
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_encrypt(&ctx, output_whole, input, INPUT_SIZE);
        // Compare
        status |= memcmp(output_chunk, output_whole, INPUT_SIZE);

        // Stream in chunks
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_stream(&ctx, output_chunk    , i);
        crypto_chacha20_stream(&ctx, output_chunk + i, INPUT_SIZE - i);
        // Stream all at once
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_stream(&ctx, output_whole, INPUT_SIZE);
        // Compare
        status |= memcmp(output_chunk, output_whole, INPUT_SIZE);
    }
    printf("%s: Chacha20 (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that output and input can be the same pointer
static int p_chacha20_same_ptr()
{
    int status = 0;
    u8  output[INPUT_SIZE];
    RANDOM_INPUT(input, INPUT_SIZE);
    RANDOM_INPUT(key  , 32);
    RANDOM_INPUT(nonce, 8);
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key, nonce);
    crypto_chacha20_encrypt(&ctx, output, input, INPUT_SIZE);
    crypto_chacha20_init   (&ctx, key, nonce);
    crypto_chacha20_encrypt(&ctx, input, input, INPUT_SIZE);
    status |= memcmp(output, input, CHACHA_BLOCK_SIZE);
    printf("%s: Chacha20 (output == input)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_chacha20_set_ctr()
{
#define STREAM_SIZE (CHACHA_BLOCK_SIZE * CHACHA_NB_BLOCKS)
    int status = 0;
    FOR (i, 0, CHACHA_NB_BLOCKS) {
        u8 output_part[STREAM_SIZE    ];
        u8 output_all [STREAM_SIZE    ];
        u8 output_more[STREAM_SIZE * 2];
        RANDOM_INPUT(key  , 32);
        RANDOM_INPUT(nonce, 8);
        size_t limit = i * CHACHA_BLOCK_SIZE;
        // Encrypt all at once
        crypto_chacha_ctx ctx;
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_stream(&ctx, output_all, STREAM_SIZE);
        // Encrypt second part
        crypto_chacha20_set_ctr(&ctx, i);
        crypto_chacha20_stream(&ctx, output_part + limit, STREAM_SIZE - limit);
        // Encrypt first part
        crypto_chacha20_set_ctr(&ctx, 0);
        crypto_chacha20_stream(&ctx, output_part, limit);
        // Compare the results (must be the same)
        status |= memcmp(output_part, output_all, STREAM_SIZE);

        // Encrypt before the begining
        crypto_chacha20_set_ctr(&ctx, -(u64)i);
        crypto_chacha20_stream(&ctx,
                               output_more + STREAM_SIZE - limit,
                               STREAM_SIZE + limit);
        // Compare the results (must be the same)
        status |= memcmp(output_more + STREAM_SIZE, output_all, STREAM_SIZE);
    }
    printf("%s: Chacha20 (set counter)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_chacha20_H()
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
        crypto_chacha20_H(out, key, in);
        crypto_chacha20_H(buffer + out_idx, buffer + key_idx, buffer + in_idx);
        status |= memcmp(out, buffer + out_idx, 32);
    }
    printf("%s: HChacha20 (overlap)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_lock_incremental()
{
    int status = 0;
    FOR (i, 0, 1000) {
        RANDOM_INPUT(key  ,  32);
        RANDOM_INPUT(nonce,  24);
        RANDOM_INPUT(ad   , 128);
        RANDOM_INPUT(plain, 256);
        // total sizes
        size_t ad_size    = rand64() % 128;
        size_t text_size  = rand64() % 256;
        // incremental sizes
        size_t ad_size1   = ad_size   == 0 ? 0 : rand64() % ad_size;
        size_t text_size1 = text_size == 0 ? 0 : rand64() % text_size;
        size_t ad_size2   = ad_size   - ad_size1;
        size_t text_size2 = text_size - text_size1;
        // incremental buffers
        u8 *ad1    = ad;    u8 *ad2    = ad + ad_size1;
        u8 *plain1 = plain; u8 *plain2 = plain + text_size1;

        u8 mac1[16], cipher1[256];
        u8 mac2[16], cipher2[256];
        crypto_lock_aead(mac1, cipher1, key, nonce,
                         ad, ad_size, plain, text_size);
        crypto_lock_ctx ctx;
        crypto_lock_init   (&ctx, key, nonce);
        crypto_lock_auth_ad(&ctx, ad1, ad_size1); // just to show ad also have
        crypto_lock_auth_ad(&ctx, ad2, ad_size2); // an incremental interface
        crypto_lock_update (&ctx, cipher2             , plain1, text_size1);
        crypto_lock_update (&ctx, cipher2 + text_size1, plain2, text_size2);
        crypto_lock_final  (&ctx, mac2);
        status |= memcmp(mac1   , mac2   , 16       );
        status |= memcmp(cipher1, cipher2, text_size);

        // Now test the round trip.
        u8 re_plain1[256];
        u8 re_plain2[256];
        status |= crypto_unlock_aead(re_plain1, key, nonce, mac1,
                                     ad, ad_size, cipher1, text_size);
        crypto_unlock_init   (&ctx, key, nonce);
        crypto_unlock_auth_ad(&ctx, ad, ad_size);
        crypto_unlock_update (&ctx, re_plain2, cipher2, text_size);
        status |= crypto_unlock_final(&ctx, mac2);
        status |= memcmp(mac1 , mac2     , 16       );
        status |= memcmp(plain, re_plain1, text_size);
        status |= memcmp(plain, re_plain2, text_size);

        // Test authentication without decryption
        crypto_unlock_init        (&ctx, key, nonce);
        crypto_unlock_auth_ad     (&ctx, ad     , ad_size  );
        crypto_unlock_auth_message(&ctx, cipher2, text_size);
        status |= crypto_unlock_final(&ctx, mac2);
        // The same, except we're supposed to reject forgeries
        if (text_size > 0) {
            cipher2[0]++; // forgery attempt
            crypto_unlock_init        (&ctx, key, nonce);
            crypto_unlock_auth_ad     (&ctx, ad     , ad_size  );
            crypto_unlock_auth_message(&ctx, cipher2, text_size);
            status |= !crypto_unlock_final(&ctx, mac2);
        }
    }
    printf("%s: aead (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Only additionnal data
static int p_auth()
{
    int status = 0;
    FOR (i, 0, 128) {
        RANDOM_INPUT(key   ,  32);
        RANDOM_INPUT(nonce ,  24);
        RANDOM_INPUT(ad    , 128);
        u8 mac1[16];
        u8 mac2[16];
        // roundtrip
        {
            crypto_lock_ctx ctx;
            crypto_lock_init   (&ctx, key, nonce);
            crypto_lock_auth_ad(&ctx, ad, i);
            crypto_lock_final  (&ctx, mac1);
            crypto_lock_aead(mac2, 0, key, nonce, ad, i, 0, 0);
            status |= memcmp(mac1, mac2, 16);
        }
        {
            crypto_unlock_ctx ctx;
            crypto_unlock_init   (&ctx, key, nonce);
            crypto_unlock_auth_ad(&ctx, ad, i);
            status |= crypto_unlock_final(&ctx, mac1);
            status |= crypto_unlock_aead(0, key, nonce, mac1, ad, i, 0, 0);
        }
    }
    printf("%s: aead (authentication)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

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
    status |= TEST(hchacha20);
    status |= TEST(xchacha20);

    printf("\nProperty based tests");
    printf("\n--------------------\n");
    status |= p_chacha20();
    status |= p_chacha20_same_ptr();
    status |= p_chacha20_set_ctr();
    status |= p_chacha20_H();
    status |= p_lock_incremental();
    status |= p_auth();
    printf("\n%s\n\n", status != 0 ? "SOME TESTS FAILED" : "All tests OK!");
    return status;
}
