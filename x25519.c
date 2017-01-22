// Simplified version of the the ref10 implementation.
// Its bigger than TweetNaCl, but nearly twice as fast.

#include "x25519.h"

typedef int32_t fe[10];

void fe_0(fe h){            for (int i = 0; i < 10; i++) h[i] = 0; }
void fe_1(fe h){ h[0] = 1;  for (int i = 1; i < 10; i++) h[i] = 0; }

void fe_add (fe h, fe f, fe g) { for (int i = 0; i < 10; i++) h[i] = f[i] + g[i];}
void fe_sub (fe h, fe f, fe g) { for (int i = 0; i < 10; i++) h[i] = f[i] - g[i];}
void fe_copy(fe h, fe f      ) { for (int i = 0; i < 10; i++) h[i] = f[i];       }

void fe_cswap(fe f, fe g, unsigned int b)
{
    for (int i = 0; i < 10; i++){
        int32_t x = (f[i] ^ g[i]) & -b;
        f[i] = f[i] ^ x;
        g[i] = g[i] ^ x;
    }
}

static uint64_t load_3(const unsigned char *in)
{
    uint64_t result;
    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    return result;
}

static uint64_t load_4(const unsigned char *in)
{
    uint64_t result;
    result = (uint64_t) in[0];
    result |= ((uint64_t) in[1]) << 8;
    result |= ((uint64_t) in[2]) << 16;
    result |= ((uint64_t) in[3]) << 24;
    return result;
}

void fe_carry(fe h, int64_t t[10])
{
    int64_t c[10]; // carry
    c[9] = (t[9] + (1ll << 24)) >> 25; t[0] += c[9] * 19; t[9] -= c[9] << 25;
    c[1] = (t[1] + (1ll << 24)) >> 25; t[2] += c[1];      t[1] -= c[1] << 25;
    c[3] = (t[3] + (1ll << 24)) >> 25; t[4] += c[3];      t[3] -= c[3] << 25;
    c[5] = (t[5] + (1ll << 24)) >> 25; t[6] += c[5];      t[5] -= c[5] << 25;
    c[7] = (t[7] + (1ll << 24)) >> 25; t[8] += c[7];      t[7] -= c[7] << 25;
    c[0] = (t[0] + (1ll << 25)) >> 26; t[1] += c[0];      t[0] -= c[0] << 26;
    c[2] = (t[2] + (1ll << 25)) >> 26; t[3] += c[2];      t[2] -= c[2] << 26;
    c[4] = (t[4] + (1ll << 25)) >> 26; t[5] += c[4];      t[4] -= c[4] << 26;
    c[6] = (t[6] + (1ll << 25)) >> 26; t[7] += c[6];      t[6] -= c[6] << 26;
    c[8] = (t[8] + (1ll << 25)) >> 26; t[9] += c[8];      t[8] -= c[8] << 26;
    for (int i = 0; i < 10; i++)
        h[i] = t[i];
}

void fe_frombytes(fe h, const unsigned char *s)
{
    int64_t t[10]; // intermediate result (may overflow 32 bits)
    t[0] =  load_4(s);
    t[1] =  load_3(s +  4) << 6;
    t[2] =  load_3(s +  7) << 5;
    t[3] =  load_3(s + 10) << 3;
    t[4] =  load_3(s + 13) << 2;
    t[5] =  load_4(s + 16);
    t[6] =  load_3(s + 20) << 7;
    t[7] =  load_3(s + 23) << 5;
    t[8] =  load_3(s + 26) << 4;
    t[9] = (load_3(s + 29) & 8388607) << 2;
    fe_carry(h, t);
}

void fe_mul121666(fe h,fe f)
{
    int64_t t[10];
    for (int i = 0; i < 10; i++)
        t[i] = f[i] * (int64_t) 121666;
    fe_carry(h, t);
}

// Rolled version of ref10.  A bit slower, but much simpler.
void fe_mul(fe h,fe f,fe g)
{
    int64_t t[10];
    for (int i = 0; i < 10; i++) {
        int64_t acc = 0;
        int64_t even_i = 1 - (i & 1);
        for (int j = 0; j < i+1; j++) {
            int64_t m1_2 = (even_i & j) + 1;
            acc += (f[j] * m1_2) * (int64_t) g[i-j];
        }
        for (int j = i+1; j < 10; j++) {
            int64_t m1_2 = (even_i & j) + 1;
            acc += (f[j] * m1_2) * (int64_t) (g[i-j+10] * 19);
        }
        t[i] = acc;
    }

    int64_t c[10]; // carry
    c[0] = (t[0] + (1ll << 25)) >> 26; t[1] += c[0];      t[0] -= c[0] << 26;
    c[4] = (t[4] + (1ll << 25)) >> 26; t[5] += c[4];      t[4] -= c[4] << 26;
    c[1] = (t[1] + (1ll << 24)) >> 25; t[2] += c[1];      t[1] -= c[1] << 25;
    c[5] = (t[5] + (1ll << 24)) >> 25; t[6] += c[5];      t[5] -= c[5] << 25;
    c[2] = (t[2] + (1ll << 25)) >> 26; t[3] += c[2];      t[2] -= c[2] << 26;
    c[6] = (t[6] + (1ll << 25)) >> 26; t[7] += c[6];      t[6] -= c[6] << 26;
    c[3] = (t[3] + (1ll << 24)) >> 25; t[4] += c[3];      t[3] -= c[3] << 25;
    c[7] = (t[7] + (1ll << 24)) >> 25; t[8] += c[7];      t[7] -= c[7] << 25;
    c[4] = (t[4] + (1ll << 25)) >> 26; t[5] += c[4];      t[4] -= c[4] << 26;
    c[8] = (t[8] + (1ll << 25)) >> 26; t[9] += c[8];      t[8] -= c[8] << 26;
    c[9] = (t[9] + (1ll << 24)) >> 25; t[0] += c[9] * 19; t[9] -= c[9] << 25;
    c[0] = (t[0] + (1ll << 25)) >> 26; t[1] += c[0];      t[0] -= c[0] << 26;

    for (int i = 0; i < 10; i++)
        h[i] = t[i];
}

// The specialised square function from ref10 is much faster, but takes
// way too much source code.
// Replace with the original ref10 implementation for 30% speedup.
void fe_sq(fe h, fe f) { fe_mul(h, f, f); }

void fe_invert(fe out,fe z)
{
    fe t0, t1, t2, t3;
    fe_sq(t0, z);  for (int i = 1; i <   1; i++) fe_sq(t0,t0);
    fe_sq(t1, t0); for (int i = 1; i <   2; i++) fe_sq(t1,t1);
    fe_mul(t1,  z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0); for (int i = 1; i <   1; i++) fe_sq(t2,t2); fe_mul(t1 , t1, t2);
    fe_sq(t2, t1); for (int i = 1; i <   5; i++) fe_sq(t2,t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); for (int i = 1; i <  10; i++) fe_sq(t2,t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); for (int i = 1; i <  20; i++) fe_sq(t3,t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); for (int i = 1; i <  10; i++) fe_sq(t2,t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); for (int i = 1; i <  50; i++) fe_sq(t2,t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); for (int i = 1; i < 100; i++) fe_sq(t3,t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); for (int i = 1; i <  50; i++) fe_sq(t2,t2); fe_mul(t1 , t2, t1);
    fe_sq(t1, t1); for (int i = 1; i <   5; i++) fe_sq(t1,t1); fe_mul(out, t1, t0);
}

void fe_tobytes(unsigned char *s, fe h)
{
    int32_t t[11];
    for (int i = 0; i < 10; i++)
        t[i] = h[i];

    int32_t q = (19 * t[9] + (((int32_t) 1) << 24)) >> 25;
    for (int i = 0; i < 10; i += 2) {
        q += t[i  ]; q >>= 26;
        q += t[i+1]; q >>= 25;
    }

    // Goal: Output t-(2^255-19)q, which is between 0 and 2^255-20.
    t[0] += 19 * q;
    // Goal: Output t-2^255 q, which is between 0 and 2^255-20.
    int32_t carry[10];
    for (int i = 0; i < 10; i += 2) {
        carry[i  ]  = t    [i  ] >> 26;
        t    [i+1] += carry[i  ]      ;
        t    [i  ] -= carry[i  ] << 26;

        carry[i+1]  = t    [i+1] >> 25;
        t    [i+2] += carry[i+1]      ;
        t    [i+1] -= carry[i+1] << 25;
    }
    //  Goal: Output t0+...+2^255 t10-2^255 q, which is between 0 and 2^255-20.
    //  Have t0+...+2^230 t9 between 0 and 2^255-1;
    //  evidently 2^255 t10-2^255 q = 0.
    //  Goal: Output t0+...+2^230 t9.
    s[ 0] =  t[0] >>  0;
    s[ 1] =  t[0] >>  8;
    s[ 2] =  t[0] >> 16;
    s[ 3] = (t[0] >> 24) | (t[1] << 2);
    s[ 4] =  t[1] >>  6;
    s[ 5] =  t[1] >> 14;
    s[ 6] = (t[1] >> 22) | (t[2] << 3);
    s[ 7] =  t[2] >>  5;
    s[ 8] =  t[2] >> 13;
    s[ 9] = (t[2] >> 21) | (t[3] << 5);
    s[10] =  t[3] >>  3;
    s[11] =  t[3] >> 11;
    s[12] = (t[3] >> 19) | (t[4] << 6);
    s[13] =  t[4] >> 2;
    s[14] =  t[4] >> 10;
    s[15] =  t[4] >> 18;
    s[16] =  t[5] >> 0;
    s[17] =  t[5] >> 8;
    s[18] =  t[5] >> 16;
    s[19] = (t[5] >> 24) | (t[6] << 1);
    s[20] =  t[6] >> 7;
    s[21] =  t[6] >> 15;
    s[22] = (t[6] >> 23) | (t[7] << 3);
    s[23] =  t[7] >> 5;
    s[24] =  t[7] >> 13;
    s[25] = (t[7] >> 21) | (t[8] << 4);
    s[26] =  t[8] >> 4;
    s[27] =  t[8] >> 12;
    s[28] = (t[8] >> 20) | (t[9] << 6);
    s[29] =  t[9] >> 2;
    s[30] =  t[9] >> 10;
    s[31] =  t[9] >> 18;
}

void crypto_x25519(uint8_t       shared_secret   [32],
                   const uint8_t your_secret_key [32],
                   const uint8_t their_public_key[32])
{
    unsigned char e[32];
    unsigned int i;
    fe x1;
    fe x2;
    fe z2;
    fe x3;
    fe z3;
    fe tmp0;
    fe tmp1;
    int pos;
    unsigned int swap;
    unsigned int b;

    for (i = 0;i < 32;++i) e[i] = your_secret_key[i];
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;
    fe_frombytes(x1,their_public_key);
    fe_1(x2);
    fe_0(z2);
    fe_copy(x3,x1);
    fe_1(z3);

    swap = 0;
    for (pos = 254;pos >= 0;--pos) {
        b = e[pos / 8] >> (pos & 7);
        b &= 1;
        swap ^= b;
        fe_cswap(x2,x3,swap);
        fe_cswap(z2,z3,swap);
        swap = b;
        fe_sub(tmp0,x3,z3);
        fe_sub(tmp1,x2,z2);
        fe_add(x2,x2,z2);
        fe_add(z2,x3,z3);
        fe_mul(z3,tmp0,x2);
        fe_mul(z2,z2,tmp1);
        fe_sq(tmp0,tmp1);
        fe_sq(tmp1,x2);
        fe_add(x3,z3,z2);
        fe_sub(z2,z3,z2);
        fe_mul(x2,tmp1,tmp0);
        fe_sub(tmp1,tmp1,tmp0);
        fe_sq(z2,z2);
        fe_mul121666(z3,tmp1);
        fe_sq(x3,x3);
        fe_add(tmp0,tmp0,z3);
        fe_mul(z3,x1,z2);
        fe_mul(z2,tmp1,tmp0);
    }
    fe_cswap(x2,x3,swap);
    fe_cswap(z2,z3,swap);

    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(shared_secret,x2);
}

void crypto_x25519_base(uint8_t public_key[32], const uint8_t secret_key[32])
{
    static const uint8_t base_point [32] = {9};
    crypto_x25519(public_key, secret_key, base_point);
}
