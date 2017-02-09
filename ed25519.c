// Taken from TweetNaCl.
// I tried the ref10 implementation, but that was too damn big

#include "ed25519.h"

#define FOR(i, start, end) for (size_t i = start; i < end; i++)
#define sv static void
#define sc static const

typedef uint8_t   u8;
typedef int64_t  i64;
typedef uint64_t u64;
typedef i64 gf[16];

sc gf gf0;
sc gf gf1 = { 1 };
sc gf  D  = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
              0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
sc gf  D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
              0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
sc gf  X  = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
              0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
sc gf  Y  = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
              0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
sc gf  I  = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
              0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

sc u64 L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };

sv car_25519(gf o)
{
    FOR(i, 0, 16) {
        o[i]              += 1LL  << 16;
        i64 c          = o[i] >> 16;
        o[(i+1) * (i<15)] += c - 1 + (37 * (c-1) * (i==15));
        o[i]              -= c << 16;
    }
}

sv sel_25519(gf p, gf q, int b)
{
    i64 c = ~(b-1);
    FOR(i, 0, 16) {
        i64 t = c & (p[i] ^ q[i]);
        p[i]     ^= t;
        q[i]     ^= t;
    }
}

sv pack_25519(u8 *o, const gf n)
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

sv A(gf o, const gf a, const gf b) { FOR(i, 0, 16) o[i] = a[i] + b[i]; }
sv Z(gf o, const gf a, const gf b) { FOR(i, 0, 16) o[i] = a[i] - b[i]; }
sv M(gf o, const gf a, const gf b)
{
    i64 t[31];
    FOR(i, 0, 31) t[i] = 0;
    FOR(i, 0, 16) FOR(j, 0, 16) t[i+j] += a[i] * b[j];
    FOR(i, 0, 15) t[i] += 38 * t[i+16];
    FOR(i, 0, 16) o[i] = t[i];
    car_25519(o);
    car_25519(o);
}
sv S(gf o,const gf a){ M(o, a, a); }

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

sv unpack_25519(gf o, const u8 *n)
{
    FOR(i, 0, 16) o[i] = n[2*i] + ((i64)n[2*i + 1] << 8);
    o[15] &= 0x7fff;
}

sv set_25519(gf r, const gf a) { FOR(i, 0, 16) r[i] = a[i]; }

static u8 par_25519(const gf a)
{
    u8 d[32];
    pack_25519(d, a);
    return d[0] & 1;
}

sv pow2523(gf o,const gf i)
{
    gf c;
    FOR(a, 0, 16) c[a] = i[a];
    for(int a = 250; a >= 0; a--) {
        S(c, c);
        if(a != 1) M(c, c, i);
    }
    FOR(a, 0, 16) o[a] = c[a];
}

static int vn(const u8 *x, const u8 *y, size_t n)
{
  uint32_t d = 0;
  FOR(i, 0, n) d |= x[i] ^ y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

static int neq_25519(const gf a, const gf b)
{
    u8 c[32],d[32];
    pack_25519(c, a);
    pack_25519(d, b);
    return vn(c, d, 32);
}

sv add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[0], p[1]);
    A(t, q[0], q[1]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, D2);
    M(d, p[2], q[2]);
    A(d, d, d);
    Z(e, b, a);
    Z(f, d, c);
    A(g, d, c);
    A(h, b, a);

    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

sv cswap(gf p[4], gf q[4], u8 b)
{
    FOR(i, 0, 4)
        sel_25519(p[i],q[i],b);
}

sv pack(u8 *r, gf p[4])
{
    gf tx, ty, zi;
    inv_25519(zi, p[2]);
    M(tx, p[0], zi);
    M(ty, p[1], zi);
    pack_25519(r, ty);
    r[31] ^= par_25519(tx) << 7;
}

sv scalarmult(gf p[4], gf q[4], const u8 *s)
{
    set_25519(p[0], gf0);
    set_25519(p[1], gf1);
    set_25519(p[2], gf1);
    set_25519(p[3], gf0);
    for (int i = 255; i >= 0; i--) {
        u8 b = (s[i/8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

sv scalarbase(gf p[4], const u8 *s)
{
    gf q[4];
    set_25519(q[0], X);
    set_25519(q[1], Y);
    set_25519(q[2], gf1);
    M(q[3], X, Y);
    scalarmult(p, q, s);
}

sv modL(u8 *r, i64 x[64])
{
    i64 i, j;
    for (i = 63;i >= 32;--i) {
        i64 carry = 0;
        for (j = i - 32;j < i - 12;++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    i64 carry = 0;
    FOR(j, 0, 32) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    FOR(j, 0, 32) x[j] -= carry * L[j];
    FOR(i, 0, 32) {
        x[i+1] += x[i] >> 8;
        r[i  ]  = x[i] & 255;
    }
}

sv reduce(u8 r[64])
{
    i64 x[64];
    FOR(i, 0, 64) x[i] = (u64) r[i];
    FOR(i, 0, 64) r[i] = 0;
    modL(r, x);
}

static int unpackneg(gf r[4],const u8 p[32])
{
    gf t, chk, num, den, den2, den4, den6;
    set_25519(r[2], gf1);
    unpack_25519(r[1], p);
    S(num,r [1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq_25519(chk, num)) M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq_25519(chk, num)) return -1;

    if (par_25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

    M(r[3], r[0], r[1]);
    return 0;
}

#ifdef ED25519_BLAKE2B
    #include "blake2b.h"
    #define HASH crypto_blake2b
#else
    #ifdef ED25519_SHA512
        #include "sha512.h"
        #define HASH crypto_sha512
    #endif
#endif

#define COMBINE1(x, y) x ## y
#define COMBINE2(x, y) COMBINE1(x, y)
#define HASH_CTX    COMBINE2(HASH, _ctx)
#define HASH_INIT   COMBINE2(HASH, _init)
#define HASH_UPDATE COMBINE2(HASH, _update)
#define HASH_FINAL  COMBINE2(HASH, _final)

// hash function interface
// Typical uses: sha512 for tests vectors, blake2b for production.
void HASH_INIT  (HASH_CTX *ctx);
void HASH_UPDATE(HASH_CTX *ctx, const u8 *in, size_t inlen);
void HASH_FINAL (HASH_CTX *ctx, u8 hash[64]);
void HASH(u8 hash[64], const u8 *in, size_t inlen);

sv hash_k(u8 k[64], const u8 R[32], const u8 A[32], const u8 *M, size_t M_size)
{
    HASH_CTX ctx;
    HASH_INIT  (&ctx);
    HASH_UPDATE(&ctx, R , 32    );
    HASH_UPDATE(&ctx, A , 32    );
    HASH_UPDATE(&ctx, M , M_size);
    HASH_FINAL (&ctx, k);
    reduce(k);
}

void crypto_ed25519_public_key(uint8_t        public_key[32],
                               const uint8_t  secret_key[32])
{
    // hash the private key, turn the hash into a scalar
    u8 a[64];
    HASH(a, secret_key, 32);
    a[ 0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    // the public key is the packed form of the point aB (B == basepoint)
    gf aB[4];
    scalarbase(aB, a);
    pack(public_key, aB);
}

void crypto_ed25519_sign(uint8_t        signature[64],
                         const uint8_t  secret_key[32],
                         const uint8_t *message,
                         size_t         message_size)
{
    u8 h[64];
    u8 *a      = h;       // secret scalar
    u8 *prefix = h + 32;  // prefix for nonce generation
    HASH(h, secret_key, 32);

    // build public key from secret key
    a[ 0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
    gf aB[4];
    scalarbase(aB, a);
    u8 public_key[32];
    pack(public_key, aB);

    // Constructs the "random" nonce from the secret key and message.
    // An actual random number would work just fine, and would save us
    // the trouble of hashing the message twice.  If we did that
    // however, the user could fuck it up and reuse the nonce.
    u8 r[64];
    HASH_CTX ctx;
    HASH_INIT  (&ctx);
    HASH_UPDATE(&ctx, prefix , 32          );
    HASH_UPDATE(&ctx, message, message_size);
    HASH_FINAL (&ctx, r);

    gf rB[4];
    reduce(r);
    scalarbase(rB, r);
    pack(signature, rB); // first half of the signature = "random" nonce

    u8 k[64];
    hash_k(k, signature, public_key, message, message_size);

    i64 s[64]; // s = r + k a
    FOR(i,  0, 32) s[i] = (u64) r[i];
    FOR(i, 32, 64) s[i] = 0;
    FOR(i, 0, 32) {
        FOR(j, 0, 32) {
            s[i+j] += k[i] * (u64) a[j];
        }
    }
    modL(signature + 32, s);  // second half of the signature = s
}

int crypto_ed25519_check(const uint8_t  signature[64],
                         const uint8_t  public_key[32],
                         const uint8_t *message,
                         size_t         message_size)
{
    gf aB[4];  if (unpackneg(aB, public_key)) return -1;   // -aB
    u8 k[64];  hash_k(k, signature, public_key, message, message_size);
    gf p[4];   scalarmult(p, aB, k);                       // p = -aB k
    gf sB[4];  scalarbase(sB, signature + 32); add(p, sB); // p = s - aB k
    u8 t[32];  pack(t, p);
    return vn(signature, t, 32); // R == s - aB k ? OK : fail
}
