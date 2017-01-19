#include "x25519.h"

#define FOR(i, start, end) for (size_t i = start; i < end; i++)
#define sv static void
typedef int64_t gf[16];

static const uint8_t _0[16];
static const uint8_t _9[32] = { 9 };
static const gf _121665 = { 0xDB41, 1 };

/* static int vn(const uint8_t *x, const uint8_t *y, size_t n) */
/* { */
/*   uint32_t d = 0; */
/*   FOR(i, 0, n) d |= x[i] ^ y[i]; */
/*   return (1 & ((d - 1) >> 8)) - 1; */
/* } */


// needed for signatures (not here)
/* sv set_25519(gf r, const gf a) */
/* { */
/*     FOR(i, 0, 16) r[i] = a[i]; */
/* } */

sv car_25519(gf o)
{
    FOR(i, 0, 16) {
        o[i]              += 1LL  << 16;
        int64_t c          = o[i] >> 16;
        o[(i+1) * (i<15)] += c - 1 + (37 * (c-1) * (i==15));
        o[i]              -= c << 16;
    }
}

sv sel_25519(gf p, gf q, int b)
{
    int64_t c = ~(b-1);
    FOR(i, 0, 16) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i]     ^= t;
        q[i]     ^= t;
    }
}

sv pack_25519(uint8_t *o, const gf n)
{
    gf t;
    FOR(i, 0, 16) t[i] = n[i];
    car_25519(t);
    car_25519(t);
    car_25519(t);
    FOR(j, 0, 2) {
        gf m;
        m[0] = t[0] - 0xffed;
        FOR(i, 1, 15) {
            m[i  ]  = t[i] - 0xffff - ((m[i-1] >> 16) & 1);
            m[i-1] &= 0xffff;
        }
        m[15]  = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b  = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        sel_25519(t, m, 1-b);
    }
    FOR(i, 0, 16) {
        o[2*i    ] = t[i] & 0xff;
        o[2*i + 1] = t[i] >> 8;
    }
}

// needed for signatures (not here)
/* static int neq_25519(const gf a, const gf b) */
/* { */
/*     uint8_t c[32],d[32]; */
/*     pack_25519(c, a); */
/*     pack_25519(d, b); */
/*     return vn(c, d, 32); */
/* } */
// needed for signatures (not here)
/* static uint8_t par_25519(const gf a) */
/* { */
/*     uint8_t d[32]; */
/*     pack_25519(d, a); */
/*     return d[0] & 1; */
/* } */

sv unpack_25519(gf o, const uint8_t *n)
{
    FOR(i, 0, 16) o[i] = n[2*i] + ((int64_t)n[2*i + 1] << 8);
    o[15] &= 0x7fff;
}

sv A(gf o, const gf a, const gf b)
{
    FOR(i, 0, 16) o[i] = a[i] + b[i];
}

sv Z(gf o, const gf a, const gf b)
{
    FOR(i, 0, 16) o[i] = a[i] - b[i];
}

sv M(gf o, const gf a, const gf b)
{
    int64_t t[31];
    FOR(i, 0, 31) t[i] = 0;
    FOR(i, 0, 16) FOR(j, 0, 16) t[i+j] += a[i] * b[j];
    FOR(i, 0, 15) t[i] += 38 * t[i+16];
    FOR(i, 0, 16) o[i] = t[i];
    car_25519(o);
    car_25519(o);
}

sv S(gf o,const gf a)
{
    M(o, a, a);
}

sv inv_25519(gf o,const gf i)
{
    gf c;
    FOR(a, 0, 16) c[a] = i[a];
    for(int a = 253; a >= 0; a--) {
        S(c, c);
        if(a != 2 && a != 4)
            M(c, c, i);
    }
    FOR(a, 0, 16) o[a] = c[a];
}
// needed for signatures (not here)
/* sv pow2523(gf o,const gf i) */
/* { */
/*     gf c; */
/*     FOR(a, 0, 16) c[a] = i[a]; */
/*     for(int a = 250; a >= 0; a--) { */
/*         S(c, c); */
/*         if(a != 1) M(c, c, i); */
/*     } */
/*     FOR(a, 0, 16) o[a] = c[a]; */
/* } */

void crypto_x25519(uint8_t q[32], const uint8_t n[32], const uint8_t p[32])
{
    uint8_t z[32];
    int64_t x[80];
    int64_t r;
    gf a, b, c, d, e, f;
    FOR(i, 0, 31) z[i] = n[i];
    z[31]  = (n[31] & 127) | 64;
    z[0 ] &= 248;
    unpack_25519(x, p);
    FOR(i, 0, 16) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for(int i = 254; i>=0; i--) {
        r = (z[i>>3] >> (i & 7)) & 1;
        sel_25519(a, b, r);
        sel_25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, _121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel_25519(a, b, r);
        sel_25519(c, d, r);
    }
    FOR(i, 0, 16) {
        x[i+16] = a[i];
        x[i+32] = c[i];
        x[i+48] = b[i];
        x[i+64] = d[i];
    }
    inv_25519(x+32, x+32);
    M(x+16, x+16, x+32);
    pack_25519(q, x+16);
}

void crypto_x25519_base(uint8_t q[32], const uint8_t n[32])
{
    crypto_x25519(q, n, _9);
}
