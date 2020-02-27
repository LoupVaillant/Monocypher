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
# Copyright (c) 2020, Loup Vaillant and Andrew Moon
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
# Written in 2020 by Loup Vaillant and Andrew Moon
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

import sys # stdin

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
    def is_positive(self)  : return self.val % self.p <= (p-1) // 2
    def is_negative(self)  : return self.val % self.p >  (p-1) // 2

    def abs(self):
        if self.is_positive(): return  self
        else                 : return -self

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
    if not is_square(n) : raise ValueError('Not a square!')
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
    u = point[0]
    return u != -A and is_square(-fe(2) * u * (u + A))

def curve_to_hash(point):
    if not can_curve_to_hash(point):
        raise ValueError('cannot curve to hash')
    u   = point[0]
    v   = point[1]
    sq1 = sqrt(-u     / (fe(2) * (u+A)))
    sq2 = sqrt(-(u+A) / (fe(2) * u    ))
    if v.is_positive(): return sq1
    else              : return sq2

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
    v = (sqrt(fe(-486664)) * u / x)
    return (u, v)

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

sqrt_mA2 = sqrt(fe(-486664)) # sqrt(-(A+2))

def fast_from_edwards(point):
    x = point[0]
    y = point[1]
    z = point[2]
    u   = z + y
    zu  = z - y
    v   = u * z * sqrt_mA2
    zv  = zu * x
    div = (zu * zv).invert()
    return (u*zv*div, v*zu*div)

def pow_p58(f): return f ** ((p-5)//8)
sqrt_half  = (fe(-1) / fe(2)) ** ((p+3)//8)
chi_minus2 = chi(fe(-2))

def invsqrt(x):
    isr = x**((p - 5) // 8)
    quartic = x * isr**2
    if quartic == fe(-1) or quartic == -sqrt1:
        isr = isr * sqrt1
    is_square = quartic == fe(1) or quartic == fe(-1)
    return isr, is_square

def fast_hash_to_curve(q):
    u = fe(2)
    ufactor = -u * sqrt1
    ufactor_sqrt = sqrt(ufactor)

    r = u * q**2
    r1 = (r + fe(1))
    num = A * (A**2 * r - r1**2)
    den = r1**3
    # x = -A / (r + 1)
    # y = x^3 + A*x^2 + x
    # y = A^3/(r + 1)^2 - A^3/(r + 1)^3 - A/(r + 1)
    # y = (A^3*r - A*(r + 1)^2) / (r + 1)^3
    isr, is_square = invsqrt(num * den)
    # if is_square: isr = sqrt(1 / (num * den))
    # if not is_square: isr = sqrt(sqrt1 / (num * den))
    x = -A * (num * r1**2 * isr**2)
    # x = -A * num * (r + 1)^2 * sqrt(1 / (num * den))^2
    # x = -A * num * (r + 1)^2 * 1 / (num * den)
    # x = -A * (r + 1)^2 * 1 / den
    # x = -A / (r + 1)
    y = num * isr
    # y = num * sqrt(1 / (num * den))
    # y = sqrt(num^2 / (num * den))
    # y = sqrt(num / den)
    qx = q**2 * ufactor
    qy = q * ufactor_sqrt
    if is_square: qx = fe(1)
    if is_square: qy = fe(1)
    x = qx * x
    # x = q^2 * -u * sqrt(-1) * -A * sqrt(-1) / (r + 1)
    # x = -A * u * q^2 / (r + 1)
    # x = -A * r / (r + 1)
    y = qy * y
    # y = q * sqrt(-u * sqrt1) * sqrt(sqrt(-1) * num / den)
    # y = sqrt(q^2 * u * num / den)
    # y = sqrt(r * num / den)
    y = y.abs()
    if is_square: y = -y
    return (x, y)

def fast_curve_to_hash(point):
    u = fe(2)
    ufactor = -u * sqrt1
    ufactor_sqrt = sqrt(ufactor)

    x, y = point
    t0 = A + x
    t1 = x
    # if is_positive(y): r = u*q^2 = -(A + x)/x
    # if is_negative(y): r = u*q^2 = -x/(A + x)
    isr, is_square = invsqrt(-t0 * t1 * u)
    # isr = sqrt(-1 / ((A + x) * x * u))
    if not is_square:
        return None
    num = t0
    if y.is_positive(): num = t1
    q = num * isr
    # if is_positive(y): q = (A + x) * sqrt(1 / (-x * (A + x) * u)) = sqrt(-(A + x) / (x * u))
    # if is_positive(y): q = sqrt(-(A + x) / (x * u))
    # if is_negative(y): q = x * sqrt(1 / (-x * (A + x) * u)) = sqrt(-x / ((A + x) * u))
    # if is_negative(y): q = sqrt(-x / ((A + x) * u))
    q = q.abs()
    return q

half_A = A // 2

# entire key generation chain
def full_cycle_check(scalar, u):
    fe(scalar).print()
    uv  = from_edwards(scalarbase(scalar))
    fuv = fast_from_edwards(fast_scalarbase(scalar))
    if fuv[0] != uv[0]: raise ValueError('Incorrect fast u')
    if fuv[1] != uv[1]: raise ValueError('Incorrect fast v')
    if uv [0] != u    : raise ValueError('Test vector failure')
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
    lines = [x.strip() for x in sys.stdin.readlines() if x.strip()]
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

