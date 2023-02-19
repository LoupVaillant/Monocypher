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
// Copyright (c) 2020, 2023 Loup Vaillant
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
// Written in 2020 and 2023 by Loup Vaillant
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
		crypto_aead_lock(cipher_text, mac, key, nonce, ad, i, plain_text, i);
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
		crypto_aead_unlock(plain_text, mac, key, nonce, ad, i, cipher_text, i);
	}
}

static void blake2b()
{
	FOR (i, 0, 256) {
		u8 hash   [ 64];
		u8 key    [ 64];
		u8 message[256];
		crypto_blake2b_keyed(hash, 64, key, 0, message, i);
	}
	FOR (i, 0, 64) {
		u8 hash   [ 64];
		u8 key    [ 64];
		u8 message[256];
		crypto_blake2b_keyed(hash, 64, key, i, message, 128);
	}
	FOR (i, 0, 64) {
		u8 hash   [ 64];
		u8 key    [ 64];
		u8 message[256];
		crypto_blake2b_keyed(hash, i, key, 0, message, 0);
	}
}

static void argon2()
{
	void *work_area = alloc(1024 * 600 * 4);
	u8    hash[ 32];
	u8    pass[ 16];
	u8    salt[ 16];
	u8    key [ 32];
	u8    ad  [128];

	crypto_argon2_config config;
	config.algorithm = CRYPTO_ARGON2_ID;
	config.nb_blocks = 600 * 4;
	config.nb_passes = 3;
	config.nb_lanes  = 4;

	crypto_argon2_inputs inputs;
	inputs.pass      = pass;
	inputs.salt      = salt;
	inputs.pass_size = sizeof(pass);
	inputs.salt_size = sizeof(salt);

	crypto_argon2_extras extras;
	extras.key       = key;
	extras.ad        = ad;
	extras.key_size  = sizeof(key);
	extras.ad_size   = sizeof(ad);

	crypto_argon2(hash, 32, work_area, config, inputs, extras);
	free(work_area);
}

static void x25519()
{
	u8 shared_key      [32];
	u8 your_secret_key [32];
	u8 their_public_key[32];
	crypto_x25519(shared_key, your_secret_key, their_public_key);
}

static void x25519_to_eddsa()
{
	u8 x25519[32];
	u8 eddsa[32];
	crypto_x25519_to_eddsa(eddsa, x25519);
}

static void eddsa_key_pair()
{
	u8 seed[32];
	u8 secret_key[64];
	u8 public_key[32];
	crypto_eddsa_key_pair(secret_key, public_key, seed);
}

static void eddsa_sign()
{
	u8 signature [64];
	u8 secret_key[64];
	u8 message   [64];
	crypto_eddsa_sign(signature, secret_key, message, 64);
}

static void eddsa_to_x25519()
{
	u8 x25519[32];
	u8 eddsa [32];
	crypto_eddsa_to_x25519(x25519, eddsa);
}

static void elligator_map()
{
	u8 curve [32];
	u8 hidden[32];
	crypto_elligator_map(curve, hidden);
}

static void elligator_rev()
{
	u8 hidden[32];
	u8 curve [32];
	u8 tweak; // The compiler notices this one is used uninitialised
	crypto_elligator_rev(hidden, curve, tweak);
}

static void elligator_key_pair()
{
	u8 hidden    [32];
	u8 secret_key[32];
	u8 seed      [32];
	crypto_elligator_key_pair(hidden, secret_key,seed);
}

static void chacha20_h()
{
	u8 out[32], key[32], in[16];
	crypto_chacha20_h(out, key, in);
}

static void chacha20_x()
{
	FOR (i, 0, 128) {
		u8 cipher_text[128];
		u8 plain_text [128];
		u8 key        [ 32];
		u8 nonce      [ 24];
		crypto_chacha20_x(cipher_text, plain_text, i,  key, nonce, 0);
	}
}

static void chacha20_djb()
{
	FOR (i, 0, 128) {
		u8 cipher_text[128];
		u8 plain_text [128];
		u8 key        [ 32];
		u8 nonce      [  8];
		crypto_chacha20_djb(cipher_text, plain_text, i,  key, nonce, 0);
	}
}

static void chacha20_ietf()
{
	FOR (i, 0, 128) {
		u8 cipher_text[128];
		u8 plain_text [128];
		u8 key        [ 32];
		u8 nonce      [ 12];
		crypto_chacha20_ietf(cipher_text, plain_text, i,  key, nonce, 0);
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
	RUN(blake2b           , "constant time");
	RUN(argon2            , "constant time"); // "use" of uninitialised value
	RUN(x25519            , "constant time");
	RUN(x25519_to_eddsa   , "constant time");
	RUN(eddsa_key_pair    , "constant time");
	RUN(eddsa_sign        , "constant time");
	printf(                 "skipped      : crypto_check.\n");
	RUN(eddsa_to_x25519   , "constant time");
	RUN(elligator_map     , "constant time");
	RUN(elligator_rev     , "1 conditional");
	RUN(elligator_key_pair, "2 conditionals");
	RUN(chacha20_h        , "constant time");
	RUN(chacha20_x        , "constant time");
	RUN(chacha20_djb      , "constant time");
	RUN(chacha20_ietf     , "constant time");
	RUN(poly1305          , "constant time");
	RUN(x25519_dirty_small, "constant time");
	RUN(x25519_dirty_fast , "constant time");
	RUN(x25519_inverse    , "constant time");

	return 0;
}
