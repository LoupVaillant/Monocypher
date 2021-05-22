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
from elligator import sqrt
from elligator import sqrtm1
from elligator import A

#########################################
# scalar multiplication (Edwards space) #
#########################################

# Edwards25519 equation (d defined below):
# -x^2 + y^2 = 1 + d*x^2*y^2
d = fe(-121665) / fe(121666)

# Point addition:
# denum = d*x1*x2*y1*y2
# x     = (x1*y2 + x2*y1) / (1 + denum)
# y     = (y1*y2 + x1*x2) / (1 - denum)
# To avoid divisions, we use affine coordinates: x = X/Z, y = Y/Z.
# We can multiply Z instead of dividing X and Y.
def point_add(a, b):
    x1, y1, z1 = a
    x2, y2, z2 = b
    denum = d*x1*x2*y1*y2
    z1z2  = z1 * z2
    z1z22 = z1z2**2
    xt    = z1z2 * (x1*y2 + x2*y1)
    yt    = z1z2 * (y1*y2 + x1*x2)
    zx    = z1z22 + denum
    zy    = z1z22 - denum
    return (xt*zy, yt*zx, zx*zy)

# Point addition, with the final division
def point_add2(p1, p2):
    x1, y1  = p1
    x2, y2  = p2
    z1, z2  = (fe(1), fe(1))
    x, y, z = point_add((x1, y1, z1), (x2, y2, z2))
    div     = z.invert()
    return (x*div, y*div)

# scalar multiplication in edwards space:
# point + point + ... + point, scalar times
# (using a double and add ladder for speed)
def ed_scalarmult(point, scalar):
    affine  = (point[0], point[1], fe(1))
    acc     = (fe(0), fe(1), fe(1))
    binary  = [int(c) for c in list(format(scalar, 'b'))]
    for i in binary:
        acc = point_add(acc, acc)
        if i == 1:
            acc = point_add(acc, affine)
    return acc

# convert the point to Montgomery (u coordinate only)
# (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
# (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
def from_edwards(point):
    x, y, z = point
    return (z + y) / (z - y)

# edwards base point
eby = fe(4) / fe(5)
ebx = sqrt((eby**2 - fe(1)) / (fe(1) + d * eby**2))
edwards_base = (ebx, eby)

############################################
# scalar multiplication (Montgomery space) #
############################################
def mt_scalarmult(u, scalar):
    x1     = u
    x2, z2 = fe(1), fe(0) # "zero" point
    x3, z3 = x1   , fe(1) # "one"  point
    binary = [int(c) for c in list(format(scalar, 'b'))]
    for b in binary:
        # Montgomery ladder step:
        # if b == 0, then (P2, P3) == (P2*2 , P2+P3)
        # if b == 1, then (P2, P3) == (P2+P3, P3*2 )
        if b == 1:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        x3, z3 = ((x2*x3 - z2*z3)**2,
                  (x2*z3 - z2*x3)**2 * x1)
        x2, z2 = ((x2**2 - z2**2)**2,
                  fe(4)*x2*z2*(x2**2 + A*x2*z2 + z2**2))
        if b == 1:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
    return x2 / z2

montgomery_base = 9

############################
# Scalarmult with cofactor #
############################

# Keeping a random cofactor is important to keep points
# indistinguishable from random.  (Else we'd notice all representatives
# represent points with cleared cofactor.  Not exactly random.)

# Point of order 8, used to add the cofactor component
low_order_point_x = sqrt((sqrt(d + fe(1)) + fe(1)) / d)
low_order_point_y = -low_order_point_x * sqrtm1
low_order_point_1 = (low_order_point_x, low_order_point_y)
low_order_point_2 = point_add2(low_order_point_1, low_order_point_1)
low_order_point_4 = point_add2(low_order_point_2, low_order_point_2)
low_order_point_8 = point_add2(low_order_point_4, low_order_point_4)
low_order_point_5 = point_add2(low_order_point_1, low_order_point_4)

def check_low_order_point():
    lop2 = low_order_point_2
    lop4 = low_order_point_4
    lop8 = low_order_point_8
    zero = (fe(0), fe(1))
    if lop8 != zero: raise ValueError('low_order_point does not have low order')
    if lop2 == zero: raise ValueError('low_order_point only has order 2')
    if lop4 == zero: raise ValueError('low_order_point only has order 4')
check_low_order_point()

# base point + low order point
ed_base_1 = point_add2(low_order_point_1, edwards_base) # in Edwards space
ed_base_5 = point_add2(low_order_point_5, edwards_base) # in Edwards space
mt_base_1 = (fe(1)+ed_base_1[1]) / (fe(1)-ed_base_1[1]) # in Montgomery space
mt_base_5 = (fe(1)+ed_base_5[1]) / (fe(1)-ed_base_5[1]) # in Montgomery space

# Clamp the scalar.
# % 8 stops subgroup attacks
# Clearing bit 255 and setting bit 254 facilitates constant time ladders.
# We're not supposed to clear the cofactor, but scalar multiplication
# usually does, and we want to reuse existing code as much as possible.
def trim(scalar):
    trimmed = scalar - scalar % 8
    trimmed = trimmed % 2**254
    trimmed = trimmed + 2**254
    return trimmed

order = 2**252 + 27742317777372353535851937790883648493

# Single scalar multiplication (in Edwards space)
def scalarmult1(scalar, cofactor):
    co_cleared = ((cofactor * 5) % 8) * order  # cleared main factor
    combined   = trim(scalar) + co_cleared
    return from_edwards(ed_scalarmult(ed_base_1, combined))

# Single scalar multiplication (in Edwards space, simplified)
def scalarmult2(scalar, cofactor):
    co_cleared = (cofactor % 8) * order  # cleared main factor
    combined   = trim(scalar) + co_cleared
    return from_edwards(ed_scalarmult(ed_base_5, combined))

# Single scalar multiplication (in Montgomery space)
def scalarmult3(scalar, cofactor):
    co_cleared = ((cofactor * 5) % 8) * order  # cleared main factor
    combined   = trim(scalar) + co_cleared
    return mt_scalarmult(mt_base_1, combined)

# Single scalar multiplication (in Montgomery space, simplified)
def scalarmult4(scalar, cofactor):
    co_cleared = (cofactor % 8) * order  # cleared main factor
    combined   = trim(scalar) + co_cleared
    return mt_scalarmult(mt_base_5, combined)

# Double scalar multiplication (reuses EdDSA code)
def scalarmult5(scalar, cofactor):
    main_point = ed_scalarmult(edwards_base     , trim(scalar))
    low_order  = ed_scalarmult(low_order_point_1, cofactor    )
    return from_edwards(point_add(main_point, low_order))

# Combine and compare all ways of doing the scalar multiplication
def scalarmult(scalar, cofactor):
    p1 = scalarmult1(scalar, cofactor)
    p2 = scalarmult2(scalar, cofactor)
    p3 = scalarmult3(scalar, cofactor)
    p4 = scalarmult4(scalar, cofactor)
    p5 = scalarmult5(scalar, cofactor)
    if p1 != p2 or p1 != p3 or p1 != p4 or p1 != p5:
        raise ValueError('Incoherent scalarmult')
    return p1
