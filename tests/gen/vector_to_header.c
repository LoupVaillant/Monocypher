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

// Transforms a test vector file (from stdin) into a C header.

#include <stdio.h>
#include <inttypes.h>
#include <stddef.h>

static int is_digit(int c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "Wrong use of vector transformer. Give one argument\n");
        return 1;
    }

    char *prefix = argv[1];
    int   c      = getchar();
    int   nb_vec = 0;

    while (c != EOF) {
        int size = 0;
        if (c == ':') {
            // Empty lines can't be C arrays.
            // We make them null pointers instead
            printf("#define %s_%d 0\n", prefix, nb_vec);
        }
        else {
            printf("uint8_t %s_%d[] = { ", prefix, nb_vec);
            while (c != ':') {
                char msb = (char)c;  c = getchar();
                char lsb = (char)c;  c = getchar();
                printf("0x%c%c, ", msb, lsb);
                size ++;
            }
            printf("};\n");
        }
        c = getchar();
        printf("#define %s_%d_size %d\n", prefix, nb_vec, size);

        // seek next line
        while (!is_digit(c) && c != ':' && c != EOF) {
            c = getchar();
        }
        nb_vec++;
    }

    printf("size_t nb_%s_vectors = %d;\n", prefix, nb_vec);

    printf("uint8_t *%s_vectors[] = { ", prefix);
    for (int i = 0; i < nb_vec; i++) {
        printf("%s_%d, ", prefix, i);
    }
    printf("};\n");

    printf("size_t %s_sizes[] = { ", prefix);
    for (int i = 0; i < nb_vec; i++) {
        printf("%s_%d_size, ", prefix, i);
    }
    printf("};\n");
}
