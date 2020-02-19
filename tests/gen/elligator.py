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

class fe:
    """Prime field over 2^255 - 19"""
    p = 2**255 - 19
    def __init__(self, x):
        self.val = x % self.p

    # Basic arithmetic operations
    def __neg__     (self   ): return fe(-self.val                            )
    def __add__     (self, o): return fe( self.val +  o.val                   )
    def __sub__     (self, o): return fe( self.val -  o.val                   )
    def __mul__     (self, o): return fe((self.val *  o.val         ) % self.p)
    def __truediv__ (self, o): return fe((self.val *  o.invert().val) % self.p)
    def __floordiv__(self, o): return fe( self.val // o                       )
    def __pow__     (self, s): return fe(pow(self.val, s       , self.p))
    def invert      (self   ): return fe(pow(self.val, self.p-2, self.p))

    def __eq__(self, other): return self.val % self.p == other.val % self.p
    def __ne__(self, other): return self.val % self.p != other.val % self.p
    def isPositive(self)   : return self.val % self.p <= (p-1) // 2

    def abs(self):
        if self.isPositive(): return  self
        else                : return -self

    def print(self):
        """prints a field element in little endian"""
        m = self.val % self.p
        for _ in range(32):
            print(format(m % 256, '02x'), end='')
            m //= 256
        if m != 0: raise ValueError('number is too big!!')
        print(':')

# Curve25519 constants
p = fe.p
A = fe(486662)
# chosen non-square: 2
# B = 1

def chi      (n): return n**((p-1)//2)
def is_square(n): return n == fe(0) or chi(n) == fe(1)

sqrt1 = ((fe(2)**((p-1) // 4)) * fe(-1)**((p+3) // 8)).abs()

def sqrt(n):
    if not(is_square(n)) : raise ValueError('Not a square!')
    root = n**((p+3) // 8)
    if root * root != n: root = (root * sqrt1)
    if root * root != n: raise ValueError('Should be a square!!')
    return root.abs()

# Elligator 2
def hash_to_curve(r):
    w = -A / (fe(1) + fe(2) * r**2)
    e = chi(w**3 + A*w**2 + w)
    u = e*w - (fe(1)-e)*(A//2)
    v = -e * sqrt(u**3 + A*u**2 + u)
    return (u, v)

def can_curve_to_hash(point):
    x = point[0]
    return x != -A and is_square(-fe(2) * x * (x + A))

def curve_to_hash(point):
    if not can_curve_to_hash(point):
        raise ValueError('cannot curve to hash')
    u   = point[0]
    v   = point[1]
    sq1 = sqrt(-u     / (fe(2) * (u+A)))
    sq2 = sqrt(-(u+A) / (fe(2) * u    ))
    if v.isPositive(): return sq1
    else             : return sq2

# round trip test
for i in range(50):
    h   = fe(1234567890 * i).invert() # "random" hash
    pp  = hash_to_curve(h)
    hh  = curve_to_hash(pp)
    ppp = hash_to_curve(hh)
    if hh != h.abs() : raise ValueError('h != hh')
    if pp != ppp     : raise ValueError('pp != ppp')

# Edwards (Edwards25519)
# -x^2 + y^2 = 1 + d*x^2*y^2
d = fe(-121665) / fe(121666)

def point_add(a, b):
    x1 = a[0];  y1 = a[1];
    x2 = b[0];  y2 = b[1];
    denum = d*x1*x2*y1*y2
    x     = (x1*y2 + x2*y1) / (fe(1) + denum)
    y     = (y1*y2 + x1*x2) / (fe(1) - denum)
    return (x, y)

def trim(scalar):
    trimmed = scalar - scalar % 8
    trimmed = trimmed % 2**254
    trimmed = trimmed + 2**254
    return trimmed

def scalarmult(point, scalar):
    acc     = (fe(0), fe(1))
    trimmed = trim(scalar)
    binary  = [int(c) for c in list(format(trimmed, 'b'))]
    for i in binary:
        acc = point_add(acc, acc)
        if i == 1:
            acc = point_add(acc, point)
    return acc

eby = fe(4) / fe(5)
ebx = sqrt((eby**2 - fe(1)) / (fe(1) + d * eby**2))
edwards_base = (ebx, eby)

def scalarbase(scalar):
    return scalarmult(edwards_base, scalar)

# conversion to Montgomery
# (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
# (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
def from_edwards(point):
    x = point[0]
    y = point[1]
    u = (fe(1) + y) / (fe(1) - y)
    v = (sqrt(fe(-486664)) * u / x).abs()
    return (u, v)

# entire key generation chain
def private_to_hash(scalar):
    xy = scalarbase(scalar)
    uv = from_edwards(xy)
    if can_curve_to_hash(uv):
        return curve_to_hash(uv)
    return None

def full_cycle_check(scalar):
    fe(scalar).print()
    xy = scalarbase(scalar)
    uv = from_edwards(xy)
    h  = private_to_hash(scalar)
    uv[0].print()
    uv[1].print()
    if h is None:
        print('00:')    # Failure
        print('00:')    # dummy value for the hash
    else:
        print('01:')    # Success
        h.print()       # actual value for the hash
        c = hash_to_curve(h)
        if c != uv:
            print('Round trip failure')

private = 0
for v in range(20):
    for i in range(32):
        private += (v+i) * 2**(8*i)
    print('')
    full_cycle_check(private)

# fast point addition & scalar multiplication with affine coordinates:
# x = X/Z, y = Y/Z. We can multiply Z instead of dividing X and Y.
# The goal is to test the merging of the final inversion
# with the exponentiations required for curve_to_hash
def fast_point_add(a, b):
    x1 = a[0];  y1 = a[1];  z1 = a[2];
    x2 = b[0];  y2 = b[1];  z2 = b[2];
    denum = d*x1*x2*y1*y2
    z1z2  = z1 * z2
    z1z22 = z1z2**2
    xt    = z1z2 * (x1*y2 + x2*y1)
    yt    = z1z2 * (y1*y2 + x1*x2)
    zx    = z1z22 + denum
    zy    = z1z22 - denum
    return (xt*zy, yt*zx, zx*zy)

def fast_scalarmult(point, scalar):
    affine  = (point[0], point[1], fe(1))
    acc     = (fe(0), fe(1), fe(1))
    trimmed = trim(scalar)
    binary  = [int(c) for c in list(format(trimmed, 'b'))]
    for i in binary:
        acc = fast_point_add(acc, acc)
        if i == 1:
            acc = fast_point_add(acc, affine)
    return acc

def fast_scalarbase(scalar):
    return fast_scalarmult(edwards_base, scalar)

# Explicit formula for hash_to_curve
# We don't need the v coordinate for X25519, so it is omited
def explicit_hash_to_curve(r):
    w = fe(2) * r**2  # fe_sq2()
    w = w + fe(1)
    w = w.invert()
    w = w * A
    w = -w
    e = A + w
    e = e * w
    e = e + fe(1)
    e = e * w
    e = chi(e)
    t = A // 2  # constant
    u = fe(1) - e
    u = u * t
    w = e * w
    u = w - u
    return u
