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
#include "c25519.h"
#include "edsign.h"

static u64 x25519(void)
{
	u8 in [32] = {9};
	u8 out[F25519_SIZE];
	FOR (i, 0, F25519_SIZE) {
		out[i] = c25519_base_x[i];
	}

	TIMING_START {
		c25519_prepare(in);
		c25519_smult(out, out, in);
	}
	TIMING_END;
}

void edsign_sec_to_pub(uint8_t *pub, const uint8_t *secret);

/* Produce a signature for a message. */
#define EDSIGN_SIGNATURE_SIZE  64

void edsign_sign(uint8_t *signature, const uint8_t *pub,
                 const uint8_t *secret,
                 const uint8_t *message, size_t len);

/* Verify a message signature. Returns non-zero if ok. */
uint8_t edsign_verify(const uint8_t *signature, const uint8_t *pub,
                      const uint8_t *message, size_t len);

static u64 edDSA_sign(void)
{
	RANDOM_INPUT(sk     , 32);
	RANDOM_INPUT(message, 64);
	u8 pk [32];
	u8 sig[64];
	edsign_sec_to_pub(pk, sk);

	TIMING_START {
		edsign_sign(sig, pk, sk, message, 64);
	}
	TIMING_END;
}

static u64 edDSA_check(void)
{
	RANDOM_INPUT(sk     , 32);
	RANDOM_INPUT(message, 64);
	u8 pk [32];
	u8 sig[64];
	edsign_sec_to_pub(pk, sk);
	edsign_sign(sig, pk, sk, message, 64);

	TIMING_START {
		if (!edsign_verify(sig, pk, message, 64)) {
			printf("c25519 verification failed\n");
		}
	}
	TIMING_END;
}

int main()
{
	print("x25519      ", x25519()     , "exchanges  per second");
	print("EdDSA(sign) ", edDSA_sign() , "signatures per second");
	print("EdDSA(check)", edDSA_check(), "checks     per second");
	printf("\n");
	return 0;
}
