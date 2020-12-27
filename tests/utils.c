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

#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void store64_le(u8 out[8], u64 in)
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
    out[4] = (in >> 32) & 0xff;
    out[5] = (in >> 40) & 0xff;
    out[6] = (in >> 48) & 0xff;
    out[7] = (in >> 56) & 0xff;
}

u32 load32_le(const u8 s[4])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16)
        | ((u32)s[3] << 24);
}

u64 load64_le(const u8 s[8])
{
    return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

// Must be seeded with a nonzero value.
// Accessible from the outside so we can modify it
u64 random_state = 12345;

// Pseudo-random 64 bit number, based on xorshift*
u64 rand64(void)
{
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    return random_state * 0x2545F4914F6CDD1D; // magic constant
}

void p_random(u8 *stream, size_t size)
{
    FOR (i, 0, size) {
        stream[i] = (u8)rand64();
    }
}

void print_vector(const u8 *buf, size_t size)
{
    FOR (i, 0, size) {
        printf("%x%x", buf[i] >> 4, buf[i] & 0x0f);
    }
    printf(":\n");
}

void print_number(u64 n)
{
    u8 buf[8];
    store64_le(buf, n);
    print_vector(buf, 8);
}

void* alloc(size_t size)
{
    if (size == 0) {
        // Some systems refuse to allocate zero bytes.
        // So we don't.  Instead, we just return a non-sensical pointer.
        // It shouldn't be dereferenced anyway.
        return NULL;
    }
    void *buf = malloc(size);
    if (buf == NULL) {
        fprintf(stderr, "Allocation failed: 0x%zx bytes\n", size);
        exit(1);
    }
    return buf;
}

static int to_num(char c)
{
    return c >= '0' && c <= '9' ? c - '0'
        :  c >= 'a' && c <= 'f' ? c - 'a' + 10
        :                         c - 'A' + 10;
}

static vector vector_of_string(const char *s)
{
    vector v;
    v.size = strlen(s) / 2;
    v.buf  = v.size == 0 ? 0 : (u8*)alloc(v.size);
    FOR (i, 0, v.size) {
        int msb = to_num(*s);  s++;
        int lsb = to_num(*s);  s++;
        v.buf[i] = msb * 16 + lsb;
    }
    return v;
}

vector next_input(vector_reader *reader)
{
    if (reader->size == 0 || reader->nb_inputs >= 10) {
        fprintf(stderr, "Input reader overload (no more vectors)\n");
        exit(1);
    }
    const char *next = *(reader->next);
    vector *input = reader->inputs + reader->nb_inputs;
    reader->next++;
    reader->size--;
    *input = vector_of_string(next);
    reader->nb_inputs++;
    return *input;
}

vector next_output(vector_reader *reader)
{
    if (reader->size == 0 || reader->nb_inputs >= 10) {
        fprintf(stderr, "Input reader overload (no more vectors)\n");
        exit(1);
    }
    const char *next = *(reader->next);
    reader->next++;
    reader->size--;
    reader->expected = vector_of_string(next);
    reader->out.size = reader->expected.size;
    reader->out.buf  = (u8*)alloc(reader->out.size);
    return reader->out;
}

int vector_test(void (*f)(vector_reader*),
                const char *name, size_t nb_vectors, const char *vectors[])
{
    int status   = 0;
    int nb_tests = 0;
    vector_reader in;
    in.size = nb_vectors;
    in.next = vectors;

    while (in.size > 0) {
        in.nb_inputs = 0;
        f(&in);
        if (in.expected.size != 0) {
            status |= memcmp(in.out.buf, in.expected.buf, in.expected.size);
        }
        FOR (i, 0, in.nb_inputs) {
            free(in.inputs[i].buf);
        }
        free(in.out.buf);
        free(in.expected.buf);
        nb_tests++;
    }
    printf("%s %4d tests: %s\n",
           status != 0 ? "FAILED" : "OK", nb_tests, name);
    return status;
}

