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

#include <sodium.h>
#include "utils.h"

static void test(u32 alg, size_t nb_blocks, size_t hash_size, size_t nb_passes)
{
	RANDOM_INPUT(password, 16                     );
	RANDOM_INPUT(salt    , crypto_pwhash_SALTBYTES);
	u8 hash[256];

	int algorithm = -1;
	switch (alg) {
	case 0:  fprintf(stderr, "Libsodium does not support Argon2d");  break;
	case 1:  algorithm = crypto_pwhash_ALG_ARGON2I13;                break;
	case 2:  algorithm = crypto_pwhash_ALG_ARGON2ID13;               break;
	default: fprintf(stderr, "Unknown algorithm");
	}

	if (crypto_pwhash(hash, hash_size, (char*)password, 16, salt,
	                  nb_passes, nb_blocks * 1024, algorithm)) {
		fprintf(stderr, "Argon2i failed.  "
		        "nb_blocks = %lu, "
		        "hash_size = %lu "
		        "nb_passes = %lu\n",
		        nb_blocks, hash_size, nb_passes);
		printf(":deadbeef:\n"); // prints a canary to fail subsequent tests
	}

	print_number(alg);
	print_number(nb_blocks);
	print_number(nb_passes);
	print_number(1);  // one lane (no parallelism)
	print_vector(password, 16);
	print_vector(salt    , crypto_pwhash_SALTBYTES);
	printf(":\n");    // no key
	printf(":\n");    // no additionnal data
	print_vector(hash, hash_size);
	printf("\n");
}

int main(void)
{
	SODIUM_INIT;
	FOR (nb_blocks, 508, 517) { test(1, nb_blocks, 32       , 3        ); }
	FOR (nb_blocks, 508, 517) { test(2, nb_blocks, 32       , 3        ); }
	FOR (hash_size,  63,  65) { test(1, 8        , hash_size, 3        ); }
	FOR (nb_passes,   3,   6) { test(1, 8        , 32       , nb_passes); }
	return 0;
}
