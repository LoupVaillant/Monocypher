#!/usr/bin/env sage

import sys
from sage.all import *

# Curve25519 constants
p = 2^255 - 19 # prime field (note that p % 8 == 5)
A = 486662
# B = 1
# chosen non-square = 2

def print_little(n):
    """prints a field element in little endian"""
    str = ""
    m = n % p
    for _ in range(32):
        byte = m % 256
        if   byte == 0: str += '00'
        elif byte < 16: str += '0' + hex(byte)
        else          : str +=       hex(byte)
        m //= 256
    if m != 0: raise ValueError('number is too big!!')
    print(str + ':')

def exp(a, b):
    """
    a^b mod p
    b must be positive
    """
    d = 1
    for i in list(Integer.binary(b)):
        d = (d*d) % p
        if Integer(i) == 1:
            d = (d*a) % p
    return d

def invert(n):
    """Modular invert of n"""
    return exp(n, p-2)

def m_abs(n):
    """Modular absolute value of n, to canonicalise square roots."""
    m = n%p
    if m <= (p-1) // 2: return m
    else              : return -m % p

def chi      (n): return exp(n, (p-1)//2)
def is_square(n): return n%p == 0 or chi(n) == 1

sqrt1 = m_abs(exp(2, (p-1) // 4) * exp(-1, (p+3) // 8))

def sqrt(n):
    if not(is_square(n)) : raise ValueError('Not a square!')
    root = exp(n, (p+3) // 8)
    if (root * root) % p == n % p : return m_abs(root)
    else                          : return m_abs(root * sqrt1)


# Elligator 2
def hash_to_curve(r):
    w = (-A * invert(1 + 2 * r^2)  ) % p
    e = (chi(w^3 + A*w^2 + w)      ) % p
    u = (e*w - (1-e)*A//2          ) % p
    v = (-e * sqrt(u^3 + A*u^2 + u)) % p
    return (u, v)

def can_curve_to_hash(point):
    x = point[0]
    return x != -A and is_square(-2 * x * (x + A))

def curve_to_hash(point):
    u   = point[0]
    v   = point[1]
    sq1 = sqrt(-u * invert(2 * (u+A)))
    sq2 = sqrt(-(u+A) * invert(2 * u))
    if v % p <= (p-1) // 2: return sq1
    else                  : return sq2

# Edwards (Edwards25519)
# -x^2 + y^2 = 1 + d*x^2*y^2
d = (-121665 * invert(121666)) % p

def point_add(a, b):
    x1 = a[0]; y1 = a[1];
    x2 = b[0]; y2 = b[1];
    x  = ((x1*y2 + x2*y1) * invert(1 + d*x1*x2*y1*y2)) % p
    y  = ((y1*y2 + x1*x2) * invert(1 - d*x1*x2*y1*y2)) % p
    return (x, y)

def trim(scalar):
    trimmed = scalar - scalar % 8
    trimmed = trimmed % 2^254
    trimmed = trimmed + 2^254
    return trimmed

def scalarmult(point, scalar):
    acc = (0, 1)
    for i in list(Integer.binary(trim(scalar))):
        acc = point_add(acc, acc)
        if Integer(i) == 1:
            acc = point_add(acc, point)
    return acc

eby = (4 * invert(5)) % p
ebx = sqrt((eby^2 - 1) * invert(1 + d * eby^2))
edwards_base = (ebx, eby)

def scalarbase(scalar):
    return scalarmult(edwards_base, scalar)

# conversion to Montgomery
# (u, v) = ((1+y)/(1-y), sqrt(-486664)*u/x)
# (x, y) = (sqrt(-486664)*u/v, (u-1)/(u+1))
def from_edwards(point):
    x = point[0]
    y = point[1]
    u = ((1 + y) * invert(1 - y)) % p
    v = m_abs(sqrt(-486664) * u * invert(x))
    return (u, v)

# entire key generation chain
def private_to_hash(scalar):
    xy = scalarbase(private)
    uv = from_edwards(xy)
    if can_curve_to_hash(uv):
        return curve_to_hash(uv)
    return None

def full_cycle_check(scalar):
    print_little(scalar)
    xy = scalarbase(private)
    uv = from_edwards(xy)
    h  = private_to_hash(scalar)
    print_little(uv[0])
    print_little(uv[1])
    if h == None:
        print('00:')    # Failure
        print('00:')    # dummy value for the hash
    else:
        print('01:')    # Success
        print_little(h) # actual value for the hash
        c = hash_to_curve(h)
        if c != uv:
            print('Round trip failure')

private = 0
for v in range(20):
    for i in range(32):
        private += (v+i) * 2^(8*i)
    print('')
    full_cycle_check(private)
