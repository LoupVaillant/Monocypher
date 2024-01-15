#! /usr/bin/env python3

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
# Copyright (c) 2023, Loup Vaillant
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
# Written in 2023 by Loup Vaillant
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

from binascii                                import hexlify
from cryptography.hazmat.primitives.hashes   import SHA512
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from random                                  import randrange
from random                                  import seed

seed(12345) # deterministic test vectors

def rand_buf(size):
    buf = bytearray(size)
    for i in range(size):
        buf[i] = randrange(0, 256)
    return bytes(buf)

def vectors(ikm_size, salt_size, info_size, okm_size):
    ikm  = rand_buf(ikm_size)
    salt = rand_buf(salt_size)
    info = rand_buf(info_size)
    okm  = HKDF(
        algorithm = SHA512(),
        length    = okm_size,
        salt      = salt,
        info      = info,
    ).derive(ikm)
    print(hexlify(ikm ).decode() + ":")
    print(hexlify(salt).decode() + ":")
    print(hexlify(info).decode() + ":")
    print(hexlify(okm ).decode() + ":")

vectors(0, 0, 0, 0)
vectors(0, 0, 0, 64)

vectors(32, 16, 8, 63)
vectors(32, 16, 8, 64)
vectors(32, 16, 8, 65)
vectors(32, 16, 8, 127)
vectors(32, 16, 8, 128)
vectors(32, 16, 8, 129)

vectors(127, 16, 8, 128)
vectors(128, 16, 8, 128)
vectors(129, 16, 8, 128)

vectors(32, 127, 8, 128)
vectors(32, 128, 8, 128)
vectors(32, 129, 8, 128)

vectors(32, 16, 127, 128)
vectors(32, 16, 128, 128)
vectors(32, 16, 129, 128)

vectors(127, 127, 127, 127)
vectors(128, 128, 128, 128)
vectors(129, 129, 129, 129)
