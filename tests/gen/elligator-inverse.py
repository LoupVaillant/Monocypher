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
# Written in 2020 by Loup Vaillant
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

from elligator import fe
from elligator import x25519_public_key
from elligator import can_curve_to_hash
from elligator import curve_to_hash
from elligator import fast_curve_to_hash
from elligator import hash_to_curve
from elligator import fast_hash_to_curve
from sys       import stdin

# Test a full round trip, and print the relevant test vectors
def full_cycle_check(private_key, u):
    fe(private_key).print()
    uv = x25519_public_key(private_key)
    if uv [0] != u: raise ValueError('Test vector failure')
    uv[0].print()
    uv[1].print()
    if can_curve_to_hash(uv):
        h  = curve_to_hash(uv)
        if h.is_negative(): raise ValueError('Non Canonical representative')
        fh = fast_curve_to_hash(uv)
        if fh != h: raise ValueError('Incorrect fast_curve_to_hash()')
        print('01:')    # Success
        h.print()       # actual value for the hash
        c = hash_to_curve(h)
        f = fast_hash_to_curve(h)
        if f != c   : raise ValueError('Incorrect fast_hash_to_curve()')
        if c != uv  : raise ValueError('Round trip failure')
    else:
        fh = fast_curve_to_hash(uv)
        if not (fh is None): raise ValueError('Fast Curve to Hash did not fail')
        print('00:')    # Failure
        print('00:')    # dummy value for the hash

# read test vectors:
def read_vector(vector): # vector: little endian hex number
    cut = vector[:64]    # remove final ':' character
    acc = 0              # final sum
    pos = 1              # power of 256
    for b in bytes.fromhex(cut):
        acc += b * pos
        pos *= 256
    return acc

def read_test_vectors():
    vectors = []
    lines = [x.strip() for x in stdin.readlines() if x.strip()]
    for i in range(len(lines) // 2):
        private = read_vector(lines[i*2    ])
        public  = read_vector(lines[i*2 + 1])
        vectors.append((private, fe(public)))
    return vectors

vectors = read_test_vectors()
for v in vectors:
    private = v[0]
    public  = v[1]
    full_cycle_check(private, public)
    print('')
