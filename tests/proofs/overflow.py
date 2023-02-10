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

def number(limit, overflow):
    if limit > overflow:
        raise AssertionError("limit exceeds overflow", limit, overflow)
    return (limit, overflow)

def add   (a, b): return number(a[0] + b[0], max(a[1], b[1]))
def sub   (a, b): return number(a[0] + b[0], max(a[1], b[1])) # still +
def mul   (a, b): return number(a[0] * b[0], max(a[1], b[1]))
def rshift(a, n): return number(a[0] >> n, a[1])
def lshift(a, n): return number(a[0] << n, a[1])
def b_and (a, n): return number(a[0] & n, a[1])

inttype = int #we're overriding int down the line
def cast(n):
    if type(n) is inttype:
        return Number(number(n, 2**16-1))
    return n

class Number:
    def __init__  (self, num  ): self.num = num
    def limit     (self)       : return self.num[0]
    def overflow  (self)       : return self.num[1]
    def __add__   (self, other): return Number(add(self.num, cast(other.num)))
    def __sub__   (self, other): return Number(sub(self.num, cast(other.num)))
    def __mul__   (self, other): return Number(mul(self.num, cast(other.num)))
    def __rshift__(self, n)    : return Number(rshift(self.num, n))
    def __lshift__(self, n)    : return Number(lshift(self.num, n))
    def __and__   (self, n)    : return Number(b_and (self.num, n))
    def __str__(self): return "Number(" + str(self.num) + ")"

def make(num, limit, overflow):
    if num is not None:
        limit = num.limit()
    return Number(number(limit, overflow))

def u16(num=None, limit = 2**16-1): return make(num, limit, 2**16-1)
def u32(num=None, limit = 2**32-1): return make(num, limit, 2**32-1)
def u64(num=None, limit = 2**64-1): return make(num, limit, 2**64-1)
unsigned = u16

def i16(num=None, limit = 2**15-1): return make(num, limit, 2**15-1)
def i32(num=None, limit = 2**31-1): return make(num, limit, 2**31-1)
def i64(num=None, limit = 2**63-1): return make(num, limit, 2**63-1)
int = i16

def ASSERT(truth):
    if not truth:
        raise AssertionError("ASSERT failed")
