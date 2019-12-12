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

#include "speed.h"
#include "utils.h"
#include "hydrogen.h"

static u64 hydro_random(void)
{
    u8 out[SIZE];
    RANDOM_INPUT(key  ,   32);
    RANDOM_INPUT(nonce,    8);

    TIMING_START {
        hydro_random_buf_deterministic(out, SIZE, key);
    }
    TIMING_END;
}

static u64 authenticated(void)
{
    u8 out[SIZE + hydro_secretbox_HEADERBYTES];
    RANDOM_INPUT(in , SIZE + 32);
    RANDOM_INPUT(key,        32);
    TIMING_START {
        hydro_secretbox_encrypt(out, in, SIZE, 0, "Benchmark", key);
    }
    TIMING_END;
}

static u64 hash(void)
{
    u8 hash[32];
    RANDOM_INPUT(in, SIZE);

    TIMING_START {
        hydro_hash_hash(hash, 32, in, SIZE, "Benchmark", 0);
    }
    TIMING_END;
}

static u64 sign(void)
{
    RANDOM_INPUT(message, 64);
    hydro_sign_keypair key_pair;
    hydro_sign_keygen(&key_pair);
    uint8_t sig[hydro_sign_BYTES];

    TIMING_START {
        hydro_sign_create(sig, message, 64, "Benchmark", key_pair.sk);
    }
    TIMING_END;
}

static u64 check(void)
{
    RANDOM_INPUT(message, 64);
    hydro_sign_keypair key_pair;
    hydro_sign_keygen(&key_pair);
    uint8_t sig[hydro_sign_BYTES];
    hydro_sign_create(sig, message, 64, "Benchmark", key_pair.sk);

    TIMING_START {
        if (hydro_sign_verify(sig, message, 64, "Benchmark", key_pair.pk)) {
            printf("LibHydrogen verification failed\n");
        }
    }
    TIMING_END;
}

int main()
{
    hydro_init();
    print("Random           ",hydro_random() *MUL,"megabytes  per second");
    print("Auth'd encryption",authenticated()*MUL,"megabytes  per second");
    print("Hash             ",hash()         *MUL,"megabytes  per second");
    print("sign             ",sign()             ,"signatures per second");
    print("check            ",check()            ,"checks     per second");
    printf("\n");
    return 0;
}
