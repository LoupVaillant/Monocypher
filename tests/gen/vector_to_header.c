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
// Copyright (c) 2017-2020, 2023 Loup Vaillant
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
// Written in 2017-2020, 2023 by Loup Vaillant
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related neighboring rights to this software to the public domain
// worldwide.  This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along
// with this software.  If not, see
// <https://creativecommons.org/publicdomain/zero/1.0/>

// Transforms a test vector file (from stdin) into a C header.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#define FOR(i, start, end) for (size_t i = (start); i < (end); i++)
#define CHECK(cond, msg) do { if (!(cond)) { panic(msg); } } while (0)

static void panic(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

static int is_digit(int c)
{
	return
		(c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F');
}

static int whitespace(int c)
{
	// Skip whitespace
	while (c == '\n') {
		c = getchar();
	}
	// Skip comment
	if (c == '#') {
		while (c != EOF && c != '\n') {
			c = getchar();
		}
		return whitespace(getchar());
	}
	CHECK(is_digit(c) || c == ':' || c == EOF, "Illegal character");
	return c; // first digit
}

int main(int argc, char** argv)
{
	CHECK(argc == 2, "Wrong use of vector transformer. Give one argument");

	char  *prefix = argv[1];
	size_t nb_vec = 0;

	printf("static const char *%s_vectors[]={\n", prefix);

	int c = whitespace(getchar());
	while (c != EOF) {
		printf("  \"");
		unsigned parity = 0;
		while (c != ':' && c != EOF) {
			parity = ~parity;
			CHECK(is_digit(c), "Not a digit");
			printf("%c", (char)c);
			c = getchar();
		}
		CHECK(parity == 0, "Odd number of digits");
		printf("\",\n");
		c = whitespace(getchar());
		nb_vec++;
	}
	printf("};\n");
	printf("static size_t nb_%s_vectors=%zu;\n", prefix, nb_vec);

	return 0;
}
