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

static void chacha20(vector_reader *reader)
{
	vector key       = next_input(reader);
	vector nonce     = next_input(reader);
	vector plain     = next_input(reader);
	u64    ctr       = load64_le(next_input(reader).buf);
	vector out       = next_output(reader);
	u64    nb_blocks = plain.size / 64 + (plain.size % 64 != 0);
	u64    new_ctr   = crypto_chacha20_djb(out.buf, plain.buf, plain.size,
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
	u32    new_ctr   = crypto_chacha20_ietf(out.buf, plain.buf, plain.size,
	                                        key.buf, nonce.buf, (u32)ctr);
	if (new_ctr - ctr != nb_blocks) {
		printf("FAILURE: IETF Chacha20 returned counter not correct: ");
	}
}

static void hchacha20(vector_reader *reader)
{
	vector key   = next_input(reader);
	vector nonce = next_input(reader);
	vector out   = next_output(reader);
	crypto_chacha20_h(out.buf, key.buf, nonce.buf);
}

static void xchacha20(vector_reader *reader)
{
	vector key       = next_input(reader);
	vector nonce     = next_input(reader);
	vector plain     = next_input(reader);
	u64    ctr       = load64_le(next_input(reader).buf);
	vector out       = next_output(reader);
	u64    nb_blocks = plain.size / 64 + (plain.size % 64 != 0);
	u64    new_ctr   = crypto_chacha20_x(out.buf, plain.buf, plain.size,
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
	crypto_aead_lock(out.buf + 16, out.buf, key.buf, nonce.buf,
	                 ad.buf, ad.size, text.buf, text.size);
}

static void blake2b(vector_reader *reader)
{
	vector msg = next_input(reader);
	vector key = next_input(reader);
	vector out = next_output(reader);
	crypto_blake2b_keyed(out.buf, out.size,
	                     key.buf, key.size,
	                     msg.buf, msg.size);
}

static void sha512(vector_reader *reader)
{
	vector in  = next_input(reader);
	vector out = next_output(reader);
	crypto_sha512(out.buf, in.buf, in.size);
}

static void sha512_hmac(vector_reader *reader)
{
	vector key = next_input(reader);
	vector msg = next_input(reader);
	vector out = next_output(reader);
	crypto_sha512_hmac(out.buf, key.buf, key.size, msg.buf, msg.size);
}

static void sha512_hkdf(vector_reader *reader)
{
	vector ikm  = next_input(reader);
	vector salt = next_input(reader);
	vector info = next_input(reader);
	vector okm  = next_output(reader);
	crypto_sha512_hkdf(okm .buf, okm .size,
	                   ikm .buf, ikm .size,
	                   salt.buf, salt.size,
	                   info.buf, info.size);
}

static void argon2(vector_reader *reader)
{
	crypto_argon2_config config;
	config.algorithm = load32_le(next_input(reader).buf);
	config.nb_blocks = load32_le(next_input(reader).buf);
	config.nb_passes = load32_le(next_input(reader).buf);
	config.nb_lanes  = load32_le(next_input(reader).buf);

	vector pass      = next_input(reader);
	vector salt      = next_input(reader);
	vector key       = next_input(reader);
	vector ad        = next_input(reader);
	vector out       = next_output(reader);
	void  *work_area = alloc(config.nb_blocks * 1024);

	crypto_argon2_inputs inputs;
	inputs.pass      = pass.buf;
	inputs.salt      = salt.buf;
	inputs.pass_size = (u32)pass.size;
	inputs.salt_size = (u32)salt.size;

	crypto_argon2_extras extras;
	extras.key       = key.buf;
	extras.ad        = ad.buf;
	extras.key_size  = (u32)key.size;
	extras.ad_size   = (u32)ad.size;

	crypto_argon2(out.buf, (u32)out.size, work_area, config, inputs, extras);
	free(work_area);
}

static void x25519(vector_reader *reader)
{
	vector scalar = next_input(reader);
	vector point  = next_input(reader);
	vector out    = next_output(reader);
	crypto_x25519(out.buf, scalar.buf, point.buf);
}

static void edDSA(vector_reader *reader)
{
	vector secret_k = next_input(reader);
	vector public_k = next_input(reader);
	vector msg      = next_input(reader);
	vector out      = next_output(reader);
	u8 fat_secret_key[64];
	memcpy(fat_secret_key     , secret_k.buf, 32);
	memcpy(fat_secret_key + 32, public_k.buf, 32);
	crypto_eddsa_sign(out.buf, fat_secret_key, msg.buf, msg.size);
}

static void edDSA_pk(vector_reader *reader)
{
	vector in  = next_input(reader);
	vector out = next_output(reader);
	u8 seed      [32];
	u8 secret_key[64];
	u8 public_key[32];
	memcpy(seed, in.buf, 32);
	crypto_eddsa_key_pair(secret_key, public_key, seed);
	memcpy(out.buf, public_key, 32);

	u8 zeroes[32] = {0};
	ASSERT_EQUAL(seed           , zeroes    , 32);
	ASSERT_EQUAL(secret_key     , in.buf    , 32);
	ASSERT_EQUAL(secret_key + 32, public_key, 32);
}

static void ed_25519(vector_reader *reader)
{
	vector secret_k = next_input(reader);
	vector public_k = next_input(reader);
	vector msg      = next_input(reader);
	vector out      = next_output(reader);
	u8 fat_secret_key[64];
	memcpy(fat_secret_key     , secret_k.buf, 32);
	memcpy(fat_secret_key + 32, public_k.buf, 32);
	crypto_ed25519_sign(out.buf, fat_secret_key, msg.buf, msg.size);
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
	crypto_elligator_map(out.buf, in.buf);
}

static void elligator_inv(vector_reader *reader)
{
	vector point   = next_input(reader);
	u8     tweak   = next_input(reader).buf[0];
	u8     failure = next_input(reader).buf[0];
	vector out     = next_output(reader);
	int    check   = crypto_elligator_rev(out.buf, point.buf, tweak);
	ASSERT((u8)check == failure);
	if (check) {
		out.buf[0] = 0;
	}
}

//@ ensures \result == 0;
static int p_wipe(void)
{
	printf("\tcrypto_wipe\n");
	u8 zeroes[50] = {0};
	FOR (i, 0, 50) {
		RANDOM_INPUT(buf, 50);
		crypto_wipe(buf, i);
		ASSERT_EQUAL(zeroes, buf, i);
	}
	return 0;
}

//@ ensures \result == 0;
static int p_eddsa_x25519(void)
{
	RANDOM_INPUT(e_seed, 32);
	u8 secret    [64];
	u8 e_public1[32]; crypto_eddsa_key_pair(secret, e_public1, e_seed);
	u8 x_private[64]; crypto_blake2b(x_private, 64, secret, 32);
	u8 x_public1[32]; crypto_eddsa_to_x25519  (x_public1, e_public1);
	u8 x_public2[32]; crypto_x25519_public_key(x_public2, x_private);
	ASSERT_EQUAL(x_public1, x_public2, 32);

	u8 e_public2[32]; crypto_x25519_to_eddsa  (e_public2, x_public1);
	ASSERT((e_public2[31] & 0x80) == 0); // x coordinate always positive

	e_public1[31] &= 0x7f;               // y coordinate back to original
	ASSERT_EQUAL(e_public1, e_public2, 32);
	return 0;
}

//@ ensures \result == 0;
static int p_dirty(void)
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
static int p_x25519_inverse(void)
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
static int p_verify16(void){ return p_verify(16, crypto_verify16); }
//@ ensures \result == 0;
static int p_verify32(void){ return p_verify(32, crypto_verify32); }
//@ ensures \result == 0;
static int p_verify64(void){ return p_verify(64, crypto_verify64); }

#define TEST(name)                                                      \
	int v_##name(void) { \
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
TEST(sha512_hmac)
//@ ensures \result == 0;
TEST(sha512_hkdf)
//@ ensures \result == 0;
TEST(argon2)
//@ ensures \result == 0;
TEST(x25519)
//@ ensures \result == 0;
TEST(edDSA)
//@ ensures \result == 0;
TEST(edDSA_pk)
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
	ASSERT(v_chacha20      () == 0);
	ASSERT(v_ietf_chacha20 () == 0);
	ASSERT(v_hchacha20     () == 0);
	ASSERT(v_xchacha20     () == 0);
	ASSERT(v_poly1305      () == 0);
	ASSERT(v_aead_ietf     () == 0);
	ASSERT(v_blake2b       () == 0);
	ASSERT(v_sha512        () == 0);
	ASSERT(v_sha512_hmac   () == 0);
	ASSERT(v_sha512_hkdf   () == 0);
	ASSERT(v_argon2        () == 0);
	ASSERT(v_x25519        () == 0);
	ASSERT(v_edDSA         () == 0);
	ASSERT(v_edDSA_pk      () == 0);
	ASSERT(v_ed_25519      () == 0);
	ASSERT(v_ed_25519_check() == 0);
	ASSERT(v_elligator_dir () == 0);
	ASSERT(v_elligator_inv () == 0);

	ASSERT(p_wipe          () == 0);
	ASSERT(p_eddsa_x25519  () == 0);
	ASSERT(p_dirty         () == 0);
	ASSERT(p_x25519_inverse() == 0);
	ASSERT(p_verify16      () == 0);
	ASSERT(p_verify32      () == 0);
	ASSERT(p_verify64      () == 0);
	return 0;
}
