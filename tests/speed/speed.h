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

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

typedef struct timespec timespec;

// TODO: provide a user defined buffer size
#define KILOBYTE 1024
#define MEGABYTE 1024 * KILOBYTE
#define SIZE     (256 * KILOBYTE)
#define MUL      (MEGABYTE / SIZE)
#define BILLION  1000000000

// Difference in nanoseconds
static u64 diff(timespec start, timespec end)
{
    return (u64)((end.tv_sec  - start.tv_sec ) * BILLION +
                 (end.tv_nsec - start.tv_nsec));
}

static u64 min(u64 a, u64 b)
{
    return a < b ? a : b;
}

static void print(const char *name, u64 duration, const char *unit)
{
    if (duration == 0) {
        printf("%s: too fast to be measured\n", name);
    } else {
        u64 speed_hz = BILLION / duration;
        printf("%s: %5" PRIu64 " %s\n", name, speed_hz, unit);
    }
}

// Note: not all systems will work well with CLOCK_PROCESS_CPUTIME_ID.
// If you get weird timings on your system, you may want to replace it
// with another clock id.  Perhaps even replace clock_gettime().
#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START                            \
    u64 duration = (u64)-1;                     \
    FOR (i, 0, 500) {                           \
        TIMESTAMP(start);

#define TIMING_END                              \
    TIMESTAMP(end);                             \
    duration = min(duration, diff(start, end)); \
    } /* end FOR*/                              \
    return duration
