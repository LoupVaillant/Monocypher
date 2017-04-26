// Some low hanging fruits to make Monocypher a bit faster.
//
// It's a nice to have, but it probably won't save you if Monocypher
// is really too slow.  If that ever happens, consider switching to 64
// bits implementations such as Donna, or even direct assembly.
//
// Using Donna's field arithmetic should yield a 5-fold speedup at
// least.  Signing can be even faster, but it takes a lot of code.
//
// On my computer, the alternate routines below makes curve25519 about
// 20% faster.  Noticable, but not worth the extra hundred lines.


// Specialised squaring function, faster than general multiplication.
sv fe_sq(fe h, const fe f)
{
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 f0_2  = f0*2;   i32 f1_2  = f1*2;   i32 f2_2  = f2*2;   i32 f3_2 = f3*2;
    i32 f4_2  = f4*2;   i32 f5_2  = f5*2;   i32 f6_2  = f6*2;   i32 f7_2 = f7*2;
    i32 f5_38 = f5*38;  i32 f6_19 = f6*19;  i32 f7_38 = f7*38;
    i32 f8_19 = f8*19;  i32 f9_38 = f9*38;

    i64 h0 = f0  *(i64)f0    + f1_2*(i64)f9_38 + f2_2*(i64)f8_19
        +    f3_2*(i64)f7_38 + f4_2*(i64)f6_19 + f5  *(i64)f5_38;
    i64 h1 = f0_2*(i64)f1    + f2  *(i64)f9_38 + f3_2*(i64)f8_19
        +    f4  *(i64)f7_38 + f5_2*(i64)f6_19;
    i64 h2 = f0_2*(i64)f2    + f1_2*(i64)f1    + f3_2*(i64)f9_38
        +    f4_2*(i64)f8_19 + f5_2*(i64)f7_38 + f6  *(i64)f6_19;
    i64 h3 = f0_2*(i64)f3    + f1_2*(i64)f2    + f4  *(i64)f9_38
        +    f5_2*(i64)f8_19 + f6  *(i64)f7_38;
    i64 h4 = f0_2*(i64)f4    + f1_2*(i64)f3_2  + f2  *(i64)f2
        +    f5_2*(i64)f9_38 + f6_2*(i64)f8_19 + f7  *(i64)f7_38;
    i64 h5 = f0_2*(i64)f5    + f1_2*(i64)f4    + f2_2*(i64)f3
        +    f6  *(i64)f9_38 + f7_2*(i64)f8_19;
    i64 h6 = f0_2*(i64)f6    + f1_2*(i64)f5_2  + f2_2*(i64)f4
        +    f3_2*(i64)f3    + f7_2*(i64)f9_38 + f8  *(i64)f8_19;
    i64 h7 = f0_2*(i64)f7    + f1_2*(i64)f6    + f2_2*(i64)f5
        +    f3_2*(i64)f4    + f8  *(i64)f9_38;
    i64 h8 = f0_2*(i64)f8    + f1_2*(i64)f7_2  + f2_2*(i64)f6
        +    f3_2*(i64)f5_2  + f4  *(i64)f4    + f9  *(i64)f9_38;
    i64 h9 = f0_2*(i64)f9    + f1_2*(i64)f8    + f2_2*(i64)f7
        +    f3_2*(i64)f6    + f4  *(i64)f5_2;

    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 << 26;
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 << 26;
    c1 = (h1 + (i64) (1<<24)) >> 25; h2 += c1;      h1 -= c1 << 25;
    c5 = (h5 + (i64) (1<<24)) >> 25; h6 += c5;      h5 -= c5 << 25;
    c2 = (h2 + (i64) (1<<25)) >> 26; h3 += c2;      h2 -= c2 << 26;
    c6 = (h6 + (i64) (1<<25)) >> 26; h7 += c6;      h6 -= c6 << 26;
    c3 = (h3 + (i64) (1<<24)) >> 25; h4 += c3;      h3 -= c3 << 25;
    c7 = (h7 + (i64) (1<<24)) >> 25; h8 += c7;      h7 -= c7 << 25;
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 << 26;
    c8 = (h8 + (i64) (1<<25)) >> 26; h9 += c8;      h8 -= c8 << 26;
    c9 = (h9 + (i64) (1<<24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 << 26;

    h[0] = h0;  h[1] = h1;  h[2] = h2;  h[3] = h3;  h[4] = h4;
    h[5] = h5;  h[6] = h6;  h[7] = h7;  h[8] = h8;  h[9] = h9;
}

// slightly faster inversion modulo 2^255 - 19
sv fe_invert(fe out, const fe z)
{
    fe t0, t1, t2, t3;
    fe_sq(t0, z );
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1,  z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);                                fe_mul(t1 , t1, t2);
    fe_sq(t2, t1); FOR (i, 1,   5) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); FOR (i, 1,  10) fe_sq(t2, t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); FOR (i, 1,  20) fe_sq(t3, t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); FOR (i, 1,  10) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); FOR (i, 1,  50) fe_sq(t2, t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); FOR (i, 1, 100) fe_sq(t3, t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); FOR (i, 1,  50) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t1, t1); FOR (i, 1,   5) fe_sq(t1, t1); fe_mul(out, t1, t0);
}

// slightly faster power to 2^252 - 3, for ed25519 decompression
void fe_pow22523(fe out, const fe z)
{
    fe t0, t1, t2;
    fe_sq(t0, z);
    fe_sq(t1,t0);                   fe_sq(t1, t1);  fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);                                  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,   5) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  FOR (i, 1,  20) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  FOR (i, 1, 100) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t0, t0);  FOR (i, 1,   2) fe_sq(t0, t0);  fe_mul(out, t0, z);
}

// Slightly faster twisted Edwards point doubling, assuming we use a
// specialised squaring function such as the above.
sv ge_double(ge *s, const ge *p)
{
    fe a, b, c, d, e, f, g, h;
    fe_sub(a, p->Y, p->X);  fe_sq(a, a);      //  A = (Y1-X1)^2
    fe_add(b, p->X, p->Y);  fe_sq(b, b);      //  B = (Y1+X1)^2
    fe_sq (c, p->T);        fe_mul(c, c, D2); //  C = T1^2 * k
    fe_sq (d, p->Z);        fe_add(d, d, d);  //  D = Z1^2 * 2
    fe_sub(e, b, a);                          //  E  = B - A
    fe_sub(f, d, c);                          //  F  = D - C
    fe_add(g, d, c);                          //  G  = D + C
    fe_add(h, b, a);                          //  H  = B + A
    fe_mul(s->X, e, f);                       //  X3 = E * F
    fe_mul(s->Y, g, h);                       //  Y3 = G * H
    fe_mul(s->Z, f, g);                       //  Z3 = F * G
    fe_mul(s->T, e, h);                       //  T3 = E * H
}
