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

from elligator import fe
from elligator import curve_to_hash
from elligator import hash_to_curve
from elligator import fast_hash_to_curve
from elligator import p
from elligator import print_raw
from random    import randrange
from random    import seed

def direct(r1, padding):
    q1 = hash_to_curve(r1)
    q2 = fast_hash_to_curve(r1)
    r2 = curve_to_hash(q1[0], q1[1].is_negative())
    if q1 != q2: raise ValueError('Incorrect fast_hash_to_curve')
    if r1 != r2: raise ValueError('Round trip failure')
    print_raw(r1.val + padding * 2**254)
    q1[0].print() # u coordinate only
    print()

direct(fe(0), 0) # representative 0 maps to point (0, 0)
direct(fe(0), 1) # representative 0 maps to point (0, 0)
direct(fe(0), 2) # representative 0 maps to point (0, 0)
direct(fe(0), 3) # representative 0 maps to point (0, 0)

# Make test vector generation deterministic, the actual randomness does
# not matter here since these are just tests.
seed(12345)

for i in range(50):
    direct(fe(randrange(0, (p-1)//2)), i % 4)
