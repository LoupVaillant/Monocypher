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

####################
# Field arithmetic #
####################
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

def print_raw(raw):
    """prints a raw element in little endian"""
    for _ in range(32):
        print(format(raw % 256, '02x'), end='')
        raw //= 256
    if raw != 0: raise ValueError('number is too big!!')
    print(':')

########################
# Curve25519 constants #
########################
p = fe.p
A = fe(486662)
# B = 1

###############
# Square root #
###############

# Legendre symbol:
# -  0 if n is zero
# -  1 if n is a non-zero square
# - -1 if n is not a square
# We take for granted that n^((p-1)/2) does what we want
def chi      (n): return n**((p-1)//2)
def is_square(n): return n == fe(0) or chi(n) == fe(1)

# square root of -1
sqrtm1 = (fe(2)**((p-1) // 4)).abs()
if sqrtm1 * sqrtm1 != fe(-1): raise ValueError('Wrong sqrtm1')

# The square root of n, if n is a square.
#
# Note that p is congruent to 5 modulo 8, so (p+3)/8 is an integer.
# If n is zero, then n^((p+3)/8) is zero (zero is its own square root).
# Otherwise:
# (n^((p+3)/8))^4 = n^((p+3)/2)
# (n^((p+3)/8))^4 = n^((p-1)/2) * n^2
# (n^((p+3)/8))^4 = chi(n)      * n^2 -- chi(n) == 1
# (n^((p+3)/8))^4 = n^2               -- because n is a non-zero square
# (n^((p+3)/8))^2 = n or -n
# case n:
#   (n^((p+3)/8))^2 = n
#    n^((p+3)/8)    = sqrt(n) or -sqrt(n)
# case -n:
#             (n^((p+3)/8))^2 = -n
#       -1  * (n^((p+3)/8))^2 =  n
#  sqrt(-1) *  n^((p+3)/8)    = sqrt(n) or -sqrt(n)
#
# We then choose the positive square root, between 0 and (p-1)/2
def sqrt(n):
    if not is_square(n) : raise ValueError('Not a square!')
    root = n**((p+3) // 8)
    if root * root != n: root = (root * sqrtm1)
    if root * root != n: raise ValueError('Should be a square!!')
    return root.abs()

###########################
# Elligator 2 (reference) #
###########################

# Elligator: Elliptic-curve points indistinguishable from uniform random strings
# by Daniel J. Bernstein, Mike Hamburg, Anna Krasnova, and Tanja Lange
# 2013
# https://elligator.cr.yp.to/

# Arbitrary non square, typically chosen to minimise computation.
# 2 and sqrt(-1) both work fairly well, but 2 seems to be more popular.
# We stick to 2 for compatibility.
non_square = fe(2)

# Representative to curve point, straight from the paper.

# Unlike the paper, curve coordinates are called (u, v) to follow
# established conventions. Thus, "v" in the paper is called "w" here.
def hash_to_curve(r):
    w = -A / (fe(1) + non_square * r**2)
    e = chi(w**3 + A*w**2 + w)
    u = e*w - (fe(1)-e)*(A//2)
    v = -e * sqrt(u**3 + A*u**2 + u)
    return (u, v)

# Test whether a point has a representative, straight from the paper.
def can_curve_to_hash(u):
    return u != -A and is_square(-non_square * u * (u+A))

# Computes the representative of a point, straight from the paper.
def curve_to_hash(u, v_is_negative):
    if not can_curve_to_hash(u):
        raise ValueError('cannot curve to hash')
    sq1  = sqrt(-u     / (non_square * (u+A)))
    sq2  = sqrt(-(u+A) / (non_square * u    ))
    if v_is_negative: return sq2
    else            : return sq1

#####################
# Elligator2 (fast) #
#####################

# Inverse square root.
# Returns (0               , True ) if x is zero.
# Returns (sqrt(1/x)       , True ) if x is non-zero square.
# Returns (sqrt(sqrt(-1)/x), False) if x is not a square.
# We do not guarantee the sign of the square root.
#
# Notes:
# Let quartic = x^((p-1)/4)
#
# x^((p-1)/2) = chi(x)
# quartic^2   = chi(x)
# quartic     = sqrt(chi(x))
# quartic     = 1 or -1 or sqrt(-1) or -sqrt(-1)
#
# Note that x is a square if quartic is 1 or -1
# There are 4 cases to consider:
#
# if   quartic         = 1  (x is a square)
# then x^((p-1)/4)     = 1
#      x^((p-5)/4) * x = 1
#      x^((p-5)/4)     = 1/x
#      x^((p-5)/8)     = sqrt(1/x) or -sqrt(1/x)
#
# if   quartic                = -1  (x is a square)
# then x^((p-1)/4)            = -1
#      x^((p-5)/4) * x        = -1
#      x^((p-5)/4)            = -1/x
#      x^((p-5)/8)            = sqrt(-1)   / sqrt(x)
#      x^((p-5)/8) * sqrt(-1) = sqrt(-1)^2 / sqrt(x)
#      x^((p-5)/8) * sqrt(-1) = -1/sqrt(x)
#      x^((p-5)/8) * sqrt(-1) = -sqrt(1/x) or sqrt(1/x)
#
# if   quartic         = sqrt(-1)  (x is not a square)
# then x^((p-1)/4)     = sqrt(-1)
#      x^((p-5)/4) * x = sqrt(-1)
#      x^((p-5)/4)     = sqrt(-1)/x
#      x^((p-5)/8)     = sqrt(sqrt(-1)/x) or -sqrt(sqrt(-1)/x)
#
# Note that the product of two non-squares is always a square:
#   For any non-squares a and b, chi(a) = -1 and chi(b) = -1.
#   Since chi(x) = x^((p-1)/2), chi(a)*chi(b) = chi(a*b) = 1.
#   Therefore a*b is a square.
#
#   Since sqrt(-1) and x are both non-squares, their product is a
#   square, and we can compute their square root.
#
# if   quartic                = -sqrt(-1)  (x is not a square)
# then x^((p-1)/4)            = -sqrt(-1)
#      x^((p-5)/4) * x        = -sqrt(-1)
#      x^((p-5)/4)            = -sqrt(-1)/x
#      x^((p-5)/8)            = sqrt(-sqrt(-1)/x)
#      x^((p-5)/8)            = sqrt( sqrt(-1)/x) * sqrt(-1)
#      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * sqrt(-1)^2
#      x^((p-5)/8) * sqrt(-1) = sqrt( sqrt(-1)/x) * -1
#      x^((p-5)/8) * sqrt(-1) = -sqrt(sqrt(-1)/x) or sqrt(sqrt(-1)/x)
def invsqrt(x):
    isr = x**((p - 5) // 8)
    quartic = x * isr**2
    if quartic == fe(-1) or quartic == -sqrtm1:
        isr = isr * sqrtm1
    is_square = quartic == fe(1) or quartic == fe(-1) or x == fe(0)
    return isr, is_square

# From the paper:
# w = -A / (fe(1) + non_square * r^2)
# e = chi(w^3 + A*w^2 + w)
# u = e*w - (fe(1)-e)*(A//2)
# v = -e * sqrt(u^3 + A*u^2 + u)
#
# Note that e is either 0, 1 or -1
# if e = 0
#   (u, v) = (0, 0)
# if e = 1
#   u = w
#   v = -sqrt(u^3 + A*u^2 + u)
# if e = -1
#   u = -w - A = w * non_square * r^2
#   v = sqrt(u^3 + A*u^2 + u)
#
# Let r1 = non_square * r^2
# Let r2 = 1 + r1
# Note that r2 cannot be zero, -1/non_square is not a square.
# We can (tediously) verify that:
#   w^3 + A*w^2 + w = (A^2*r1 - r2^2) * A / r2^3
# Therefore:
#   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) * (A / r2^3))
#   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) * (A / r2^3)) * 1
#   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) * (A / r2^3)) * chi(r2^6)
#   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) * (A / r2^3)  *     r2^6)
#   chi(w^3 + A*w^2 + w) = chi((A^2*r1 - r2^2) *  A * r2^3)
# Corollary:
#   e =  1 if (A^2*r1 - r2^2) *  A * r2^3) is a non-zero square
#   e = -1 if (A^2*r1 - r2^2) *  A * r2^3) is not a square
#   Note that w^3 + A*w^2 + w (and therefore e) can never be zero:
#     w^3 + A*w^2 + w = w * (w^2 + A*w + 1)
#     w^3 + A*w^2 + w = w * (w^2 + A*w + A^2/4 - A^2/4 + 1)
#     w^3 + A*w^2 + w = w * (w + A/2)^2        - A^2/4 + 1)
#     which is zero only if:
#       w = 0                   (impossible)
#       (w + A/2)^2 = A^2/4 - 1 (impossible, because A^2/4-1 is not a square)
#
# Let isr   = invsqrt((A^2*r1 - r2^2) *  A * r2^3)
#     isr   = sqrt(1        / ((A^2*r1 - r2^2) *  A * r2^3)) if e =  1
#     isr   = strt(sqrt(-1) / ((A^2*r1 - r2^2) *  A * r2^3)) if e = -1
#
# if e = 1
#   let u1 = -A * (A^2*r1 - r2^2) * A * r2^2 * isr^2
#       u1 = w
#       u1 = u
#   let v1 = -(A^2*r1 - r2^2) * A * isr
#       v1 = -sqrt((A^2*r1 - r2^2) * A / r2^3)
#       v1 = -sqrt(w^3 + A*w^2 + w)
#       v1 = -sqrt(u^3 + A*u^2 + u)   (because u = w)
#       v1 = v
#
# if e = -1
#   let ufactor = -non_square * sqrt(-1) * r^2
#   let vfactor = sqrt(ufactor)
#   let u2 = -A * (A^2*r1 - r2^2) * A * r2^2 * isr^2 * ufactor
#       u2 = w * -1 * -non_square * r^2
#       u2 = w * non_square * r^2
#       u2 = u
#   let v2 = (A^2*r1 - r2^2) * A * isr * vfactor
#       v2 = sqrt(non_square * r^2 * (A^2*r1 - r2^2) * A / r2^3)
#       v2 = sqrt(non_square * r^2 * (w^3 + A*w^2 + w))
#       v2 = sqrt(non_square * r^2 * w * (w^2 + A*w + 1))
#       v2 = sqrt(u (w^2 + A*w + 1))
#       v2 = sqrt(u ((-u-A)^2 + A*(-u-A) + 1))
#       v2 = sqrt(u (u^2 + A^2 + 2*A*u - A*u -A^2) + 1))
#       v2 = sqrt(u (u^2 + A*u + 1))
#       v2 = sqrt(u^3 + A*u^2 + u)
#       v2 = v
ufactor = -non_square * sqrtm1
vfactor = sqrt(ufactor)

def fast_hash_to_curve(r):
    t1 = r**2 * non_square    # r1
    u  = t1 + fe(1)           # r2
    t2 = u**2
    t3 = (A**2 * t1 - t2) * A # numerator
    t1 = t2 * u               # denominator
    t1, is_square = invsqrt(t3 * t1)
    u  = r**2 * ufactor
    v  = r    * vfactor
    if is_square: u = fe(1)
    if is_square: v = fe(1)
    v  = v * t3 * t1
    t1 = t1**2
    u  = u * -A * t3 * t2 * t1
    if is_square != v.is_negative(): # XOR
        v = -v
    return (u, v)

# From the paper:
# Let sq = -non_square * u * (u+A)
# if sq is not a square, or u = -A, there is no mapping
# Assuming there is a mapping:
#    if v is positive: r = sqrt(-u     / (non_square * (u+A)))
#    if v is negative: r = sqrt(-(u+A) / (non_square * u    ))
#
# We compute isr = invsqrt(-non_square * u * (u+A))
# if it wasn't a square, abort.
# else, isr = sqrt(-1 / (non_square * u * (u+A))
#
# If v is positive, we return isr * u:
#   isr * u = sqrt(-1 / (non_square * u * (u+A)) * u
#   isr * u = sqrt(-u / (non_square * (u+A))
#
# If v is negative, we return isr * (u+A):
#   isr * (u+A) = sqrt(-1     / (non_square * u * (u+A)) * (u+A)
#   isr * (u+A) = sqrt(-(u+A) / (non_square * u)
def fast_curve_to_hash(u, v_is_negative):
    t = u + A
    r = -non_square * u * t
    isr, is_square = invsqrt(r)
    if not is_square:
        return None
    if v_is_negative: u = t
    r = u * isr
    r = r.abs()
    return r
