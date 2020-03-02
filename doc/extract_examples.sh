#! /bin/sh

# This file is dual-licensed.  Choose whichever licence you want from
# the two licences listed below.
#
# The first licence is a regular 2-clause BSD licence.  The second licence
# is the CC-0 from Creative Commons. It is intended to release Monocypher
# to the public domain.  The BSD licence serves as a fallback option.
#
# SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
#
# ------------------------------------------------------------------------
#
# Copyright (c) 2019 Michael Savage
# Copyright (c) 2020 Fabio Scotoni
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ------------------------------------------------------------------------
#
# Written in 2019-2020 by Michael Savage and Fabio Scotoni
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

cat << END
#include <stdio.h>
#include <stdlib.h>
#include "../src/monocypher.h"
#include "../src/optional/monocypher-ed25519.h"

typedef struct SHA2_CTX { void *x; } SHA2_CTX;
void SHA512Init(SHA2_CTX*);
void SHA512Update(SHA2_CTX*, const void*, size_t);
void SHA512Final(uint8_t*, SHA2_CTX*);
void arc4random_buf(void*, size_t);


int main() {
END

for f in man/man3/*.3monocypher man/man3/optional/*.3monocypher
do
    # crypto_sign_init_first_pass_custom_hash examples are more complicated
    # and can't be tested like this
    if [ ! -h "$f" ] && [ "$f" != "man/man3/crypto_sign_init_first_pass_custom_hash.3monocypher" ]
    then
        echo "// $f"
        cat "$f" | sed -n "/^\.Bd/,/^\.Ed/p" | sed "s/\.Bd.*/{/" | sed "s/\.Ed/}/"
    fi
done

echo "return 0;"
echo "}"
