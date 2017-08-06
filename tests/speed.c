#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "rename_monocypher.h"
#include "rename_sha512.h"
#include "tweetnacl/tweetnacl.h"
#include "poly1305-donna/poly1305-donna.h"
#include "ed25519-donna/ed25519.h"

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
typedef uint8_t u8;
typedef uint64_t u64;
typedef struct timespec timespec;

#define SIZE (1024 * 1024)

// Deterministic "random" number generator, so we can make "random", yet
// reproducible tests.  To change the random stream, change the seed.
void p_random(u8 *stream, size_t size)
{
    static rename_chacha_ctx ctx;
    static int is_init = 0;
    if (!is_init) {
        static const u8 seed[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        rename_chacha20_init(&ctx, seed, seed);
        is_init = 1;
    }
    rename_chacha20_stream(&ctx, stream, size);
}

timespec diff(timespec start, timespec end)
{
    timespec duration;
    duration.tv_sec  = end.tv_sec  - start.tv_sec;
    duration.tv_nsec = end.tv_nsec - start.tv_nsec;
    if (duration.tv_nsec < 0) {
        duration.tv_nsec += 1000000000;
        duration.tv_sec  -= 1;
    }
    return duration;
}

timespec min(timespec a, timespec b)
{
    if (a.tv_sec < b.tv_sec ||
        (a.tv_sec == b.tv_sec && a.tv_nsec < b.tv_nsec)) {
        return a;
    }
    return b;
}

typedef struct {
    int time;
    int ratio;
} speed_t;

speed_t speed(timespec ref, timespec t)
{
    u64 ref_u = ref.tv_sec * 1000000000 + ref.tv_nsec;
    u64 t_u   = t  .tv_sec * 1000000000 + t  .tv_nsec;
    speed_t s;
    s.ratio = (100 * ref_u) / t_u; // assuming t_u is never zero
    s.time  = t_u / 1000;
    return s;
}

static void print(const char *name, speed_t result, const char *lib_name)
{
    printf("%s: %4d micro-secs, ", name, result.time);
    if (result.ratio == 100) {
        printf("As fast as %s\n", lib_name);
    } else if (result.ratio <  100) {
        printf("%4d%% slower than %s\n", 100 - result.ratio, lib_name);
    }
    else {
        printf("%4d%% faster than %s\n", result.ratio - 100, lib_name);
    }
}

#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START(duration)                  \
    timespec duration;                          \
    duration.tv_sec  = 3600 * 24;               \
    duration.tv_nsec = 0;                       \
    FOR (i, 0, 30) {                            \
        TIMESTAMP(start);

#define TIMING_END(duration)                    \
    TIMESTAMP(end);                             \
    duration = min(diff(start, end), duration); \
    }

#define TIMING_RESULT(name, result_size)                          \
    if (rename_memcmp(mono, sodium, result_size) != 0) {          \
        printf(name " benchmark failed (different results)\n");   \
    }                                                             \
    return speed(libsodium, monocypher)


static speed_t chacha20(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  nonce [   8];  p_random(nonce,    8);
    static u8  mono  [SIZE];
    static u8  sodium[SIZE];

    TIMING_START(monocypher) {
        rename_chacha_ctx ctx;
        rename_chacha20_init(&ctx, key, nonce);
        rename_chacha20_encrypt(&ctx, mono, in, SIZE);
    } TIMING_END(monocypher);
    TIMING_START(libsodium) {
        crypto_stream_chacha20_xor(sodium, in, SIZE, nonce, key);
    } TIMING_END(libsodium);

    TIMING_RESULT("Chacha20", SIZE);
}

static speed_t poly1305(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  mono  [  16];
    static u8  sodium[  16];

    TIMING_START(monocypher) {
        rename_poly1305_auth(mono, in, SIZE, key);
    }
    TIMING_END(monocypher);
    TIMING_START(libsodium) {
        crypto_onetimeauth(sodium, in, SIZE, key);
    }
    TIMING_END(libsodium);

    TIMING_RESULT("Poly1305", 16);
}

static speed_t blake2b(void)
{
    static u8 in    [SIZE];  p_random(in , SIZE);
    static u8 key   [  32];  p_random(key,   32);
    static u8 mono  [  64];
    static u8 sodium[  64];

    TIMING_START(monocypher) {
        rename_blake2b_general(mono, 64, key, 32, in, SIZE);
    }
    TIMING_END(monocypher);
    TIMING_START(libsodium) {
        crypto_generichash(sodium, 64, in, SIZE, key, 32);
    }
    TIMING_END(libsodium);

    TIMING_RESULT("Blake2b", 64);
}

static speed_t argon2i(void)
{
    size_t    nb_blocks = SIZE / 1024;
    static u8 work_area[SIZE];
    static u8 password [  16];  p_random(password, 16);
    static u8 salt     [  16];  p_random(salt    , 16);
    static u8 mono     [  32];
    static u8 sodium   [  32];

    TIMING_START(monocypher) {
        rename_argon2i(mono, 32, work_area, nb_blocks, 3,
                       password, 16, salt, 16, 0, 0, 0, 0);
    }
    TIMING_END(monocypher);

    TIMING_START(libsodium) {
        if (crypto_pwhash(sodium, 32, (char*)password, 16, salt,
                          3, nb_blocks * 1024, crypto_pwhash_ALG_DEFAULT)) {
            printf("Libsodium Argon2i failed to execute\n");
        }
    }
    TIMING_END(libsodium);

    TIMING_RESULT("Argon2i", 32);
}

static speed_t x25519(void)
{
    u8 mono_in  [32] = {9};
    u8 mono     [32] = {9};
    u8 sodium_in[32] = {9};
    u8 sodium   [32] = {9};

    TIMING_START(monocypher) {
        if (rename_x25519(mono, mono, mono_in)) {
            printf("Monocypher x25519 rejected public key\n");
        }
    }
    TIMING_END(monocypher);
    TIMING_START(libsodium) {
        if (crypto_scalarmult(sodium, sodium, sodium_in)) {
            printf("Libsodium x25519 rejected public key\n");
        }
    }
    TIMING_END(libsodium);

    TIMING_RESULT("x25519", 32);
}

static void ed25519(void)
{
    u8 sk       [32];   p_random(sk, 32);
    u8 sk_sodium[64];
    u8 pk       [64];
    crypto_sign_seed_keypair(pk, sk_sodium, sk);

    u8 message   [64];  p_random(message, 64);
    u8 mono_sig  [64];
    u8 sodium_sig[64];

    // Testing signature speed
    TIMING_START(monocypher_sig) {
        rename_sign(mono_sig, sk, pk, message, 64);
    }
    TIMING_END(monocypher_sig);
    TIMING_START(libsodium_sig) {
        crypto_sign_detached(sodium_sig, 0, message, 64, sk_sodium);
    }
    TIMING_END(libsodium_sig);


    // testing verification speed (for correct signatures)
    TIMING_START(monocypher_chk) {
        if (rename_check(mono_sig, pk, message, 64)) {
            printf("Monocypher verification failed\n");
        }
    }
    TIMING_END(monocypher_chk);
    TIMING_START(libsodium_chk) {
        if (crypto_sign_verify_detached(sodium_sig, message, 64, pk)) {
            printf("Libsodium verification failed\n");
        }
    }
    TIMING_END(libsodium_chk);


    if (rename_memcmp(mono_sig, sodium_sig, 64) != 0) {
        printf("ed25519 benchmark failed (different results)\n");
    }
    print("ed25519(sig)", speed(libsodium_sig, monocypher_sig), "Libsodium");
    print("ed25519(chk)", speed(libsodium_chk, monocypher_chk), "Libsodium");
}

#define T_TIMING_RESULT(name, result_size)                               \
    printf(rename_memcmp(mono, sodium, result_size) != 0 ? "! " : "  "); \
    return speed(libsodium, monocypher)

static speed_t t_chacha20(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  nonce [   8];  p_random(nonce,    8);
    static u8  mono  [SIZE];
    static u8  sodium[SIZE];

    TIMING_START(monocypher) {
        rename_chacha_ctx ctx;
        rename_chacha20_init(&ctx, key, nonce);
        rename_chacha20_encrypt(&ctx, mono, in, SIZE);
    }
    TIMING_END(monocypher);
    TIMING_START(libsodium) {
        tweet_stream_salsa20_crypto_xor(sodium , in, SIZE, nonce, key);
    }
    TIMING_END(libsodium);

    T_TIMING_RESULT("Chacha20", SIZE);
}

static speed_t t_poly1305(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  mono  [  16];
    static u8  sodium[  16];

    TIMING_START(monocypher) {
        rename_poly1305_auth(mono, in, SIZE, key);
    }
    TIMING_END(monocypher);
    TIMING_START(libsodium) {
        tweet_onetimeauth_poly1305_crypto(sodium , in, SIZE, key);
    }
    TIMING_END(libsodium);

    T_TIMING_RESULT("Poly1305", 16);
}

static speed_t t_blake2b(void)
{
    static u8 in    [SIZE];  p_random(in , SIZE);
    static u8 key   [  32];  p_random(key,   32);
    static u8 mono  [  64];
    static u8 sodium[  64];

    TIMING_START(monocypher) {
        rename_blake2b_general(mono, 64, key, 32, in, SIZE);
    }
    TIMING_END(monocypher);

    TIMING_START(libsodium) {
        tweet_hash_sha512_crypto(sodium, in, SIZE);
    }
    TIMING_END(libsodium);

    T_TIMING_RESULT("Blake2b", 64);
}

static speed_t t_sha512(void)
{
    static u8 in    [SIZE];  p_random(in , SIZE);
    static u8 key   [  32];  p_random(key,   32);
    static u8 mono  [  64];
    static u8 sodium[  64];

    TIMING_START(monocypher) {
        rename_sha512(mono, in, SIZE);
    }
    TIMING_END(monocypher);

    TIMING_START(libsodium) {
        tweet_hash_sha512_crypto(sodium, in, SIZE);
    }
    TIMING_END(libsodium);

    T_TIMING_RESULT("Blake2b", 64);
}


static speed_t t_x25519(void)
{
    u8 mono_in  [32] = {9};
    u8 mono     [32] = {9};
    u8 sodium_in[32] = {9};
    u8 sodium   [32] = {9};

    TIMING_START(monocypher) {
        if (rename_x25519(mono, mono, mono_in)) {
            printf("Monocypher x25519 rejected public key\n");
        }
    }
    TIMING_END(monocypher);

    TIMING_START(libsodium) {
        if (tweet_scalarmult_curve25519_crypto(sodium, sodium, sodium_in)) {
            printf("Libsodium x25519 rejected public key\n");
        }
    }
    TIMING_END(libsodium);

    T_TIMING_RESULT("x25519", 32);
}

static void t_ed25519(void)
{
    u8 sk       [32];   p_random(sk, 32);
    u8 sk_sodium[64];
    u8 pk       [64];
    crypto_sign_seed_keypair(pk, sk_sodium, sk);

    u8 message   [ 64];  p_random(message  , 64);
    u8 mono_sig  [ 64];
    u8 sodium_sig[128];

    // Testing signature speed
    TIMING_START(monocypher_sig) {
        rename_sign(mono_sig, sk, pk, message, 64);
    }
    TIMING_END(monocypher_sig);

    TIMING_START(libsodium_sig) {
        long long unsigned sm_len;
        tweet_sign(sodium_sig, &sm_len, message, 64, sk_sodium);
    }
    TIMING_END(libsodium_sig);

    if (rename_memcmp(mono_sig, sodium_sig, 64) != 0) {
        printf("ed25519 benchmark failed (different results)\n");
    }
    if (rename_memcmp(message, sodium_sig + 64, 64) != 0) {
        printf("ed25519 benchmark failed (message not copied)\n");
    }

    // testing verification speed (for correct signatures)
    TIMING_START(monocypher_chk) {
        if (rename_check(mono_sig, pk, message, 64)) {
            printf("Monocypher verification failed\n");
        }
    }
    TIMING_END(monocypher_chk);

    TIMING_START(libsodium_chk) {
        u8 m[128]; // 64 bytes for the message, plus 64 bytes of work space
        long long unsigned m_len;
        if (tweet_sign_open(m, &m_len, sodium_sig, 128, pk)) {
            printf("TweetNaCl verification failed\n");
        }
    }
    TIMING_END(libsodium_chk);

    print("  ed25519(sig)", speed(libsodium_sig, monocypher_sig), "TweetNaCl");
    print("  ed25519(chk)", speed(libsodium_chk, monocypher_chk), "TweetNaCl");
}

static speed_t d_poly1305(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  mono  [  16];
    static u8  sodium[  16];

    TIMING_START(monocypher) {
        rename_poly1305_auth(mono, in, SIZE, key);
    }
    TIMING_END(monocypher);
    TIMING_START(libsodium) {
        poly1305_auth(sodium, in, SIZE, key);
    }
    TIMING_END(libsodium);

    TIMING_RESULT("Poly1305", 16);
}

static void d_ed25519(void)
{
    u8 sk       [32];   p_random(sk, 32);
    u8 pk       [32];
    ed25519_publickey(sk, pk);

    u8 message   [64];  p_random(message, 64);
    u8 mono_sig  [64];
    u8 sodium_sig[64];

    // Testing signature speed
    TIMING_START(monocypher_sig) {
        rename_sign(mono_sig, sk, pk, message, 64);
    }
    TIMING_END(monocypher_sig);
    TIMING_START(libsodium_sig) {
        ed25519_sign(message, 64, sk, pk, sodium_sig);
    }
    TIMING_END(libsodium_sig);

    // testing verification speed (for correct signatures)
    TIMING_START(monocypher_chk) {
        if (rename_check(mono_sig, pk, message, 64)) {
            printf("Monocypher verification failed\n");
        }
    }
    TIMING_END(monocypher_chk);
    TIMING_START(libsodium_chk) {
        if (ed25519_sign_open(message, 64, pk, sodium_sig)) {
            printf("ed25519-donna verification failed\n");
        }
    }
    TIMING_END(libsodium_chk);


    if (rename_memcmp(mono_sig, sodium_sig, 64) != 0) {
        printf("ed25519 benchmark failed (different results)\n");
    }
    print("ed25519(sig)", speed(libsodium_sig, monocypher_sig),
          "32 bits ed25519-donna");
    print("ed25519(chk)", speed(libsodium_chk, monocypher_chk),
          "32 bits ed25519-donna");
}

int main()
{
    printf("\nComparing with Libsodium\n");
    printf("------------------------\n");
    print("Chacha20    ", chacha20(), "Libsodium");
    print("Poly1305    ", poly1305(), "Libsodium");
    print("Blake2b     ", blake2b (), "Libsodium");
    print("Argon2i     ", argon2i (), "Libsodium");
    print("x25519      ", x25519  (), "Libsodium");
    ed25519();

    printf("\nComparing with TweetNaCl "
           "(apple to orange comparisons are marked with a '!')\n");
    printf("------------------------\n");
    print("Chacha20    ", t_chacha20(), "TweetNaCl's Salsa20");
    print("Poly1305    ", t_poly1305(), "TweetNaCl");
    print("Blake2b     ", t_blake2b (), "TweetNaCl's Sha512");
    print("Sha512      ", t_sha512  (), "TweetNaCl");
    print("x25519      ", t_x25519  (), "TweetNaCl");
    t_ed25519 ();

    printf("\nComparing with Donna\n");
    printf("----------------------\n");
    print("Poly1305    ", d_poly1305(), "32 bit Poly1305 Donna");
    d_ed25519();

    printf("\n");
    return 0;
}
