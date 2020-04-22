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
# Copyright (c) 2020, Loup Vaillant
# Copyright (c) 2020, Fabio Scotoni
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
# Written in 2020 by Loup Vaillant and Fabio Scotoni
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

from elligator import can_curve_to_hash
from elligator import curve_to_hash
from elligator import fast_curve_to_hash
from elligator import hash_to_curve
from elligator import print_raw

from elligator_scalarmult import scalarmult

from random import randrange
from random import seed

def private_to_curve_and_hash(scalar, tweak):
    cofactor      = scalar % 8
    v_is_negative = tweak % 2 == 1;
    msb           = (tweak // 2**6) * 2**254
    u             = scalarmult(scalar, cofactor)
    r1 = None
    if can_curve_to_hash(u):
        r1 = curve_to_hash(u, v_is_negative)
    r2 = fast_curve_to_hash(u, v_is_negative)
    if r1 != r2: raise ValueError('Incoherent hash_to_curve')
    if r1 is None:
        return u, None
    if r1.val > 2**254: raise ValueError('Representative too big')
    u2, v2 = hash_to_curve(r1)
    if u2 != u: raise ValueError('Round trip failure')
    return (u, r1.val + msb)

# Make test vector generation deterministic, the actual randomness does
# not matter here since these are just tests.
seed(12345)

# All possible failures
for cofactor in range(8):
    tweak = randrange(0, 256)
    while True:
        scalar = randrange(0, 2**253) * 8 + cofactor
        u, r   = private_to_curve_and_hash(scalar, tweak)
        if r is None:
            u.print()
            print(format(tweak, '02x') + ":")
            print('ff:') # Failure
            print('00:') # dummy value for the hash
            print()
            break

# All possible successes
for cofactor in range(8):
    for sign in range(2):
        for msb in range(4):
            tweak = sign + randrange(0, 32) * 2 + msb * 64
            while True:
                scalar = randrange(0, 2**253) * 8 + cofactor
                u, r   = private_to_curve_and_hash(scalar, tweak)
                if r is not None:
                    u.print()
                    print(format(tweak, '02x') + ":")
                    print('00:') # Success
                    print_raw(r)
                    print()
                    break
