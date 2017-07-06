#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "rename_monocypher.h"

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
typedef uint8_t u8;
typedef uint64_t u64;
typedef struct timespec timespec;

#define SIZE (1024 * 1024 * 4)

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

int speed(timespec ref, timespec t)
{
    u64 ref_u = ref.tv_sec * 1000000000 + ref.tv_nsec;
    u64 t_u   = t  .tv_sec * 1000000000 + t  .tv_nsec;
    return (100 * ref_u) / t_u; // assuming t_u is never zero
}

#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START(duration)                      \
    timespec duration; duration.tv_sec = 3600 * 24; \
    FOR (i, 0, 10) {                                \
        TIMESTAMP(start)

#define TIMING_END(duration)                    \
    TIMESTAMP(end);                             \
    duration = min(diff(start, end), duration); \
    }                                           \

#define TIMING_RESULT(name, result_size)                          \
    if (rename_memcmp(mono, sodium, result_size) != 0) {          \
        printf(name " benchmark failed (different results)\n");   \
    }                                                             \
    return speed(libsodium, monocypher)


static int chacha20(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  nonce [   8];  p_random(nonce,    8);
    static u8  mono  [SIZE];
    static u8  sodium[SIZE];

    TIMING_START(monocypher);
    rename_chacha_ctx ctx;
    rename_chacha20_init(&ctx, key, nonce);
    rename_chacha20_encrypt(&ctx, mono, in, SIZE);
    TIMING_END(monocypher);

    TIMING_START(libsodium);
    crypto_stream_chacha20_xor(sodium, in, SIZE, nonce, key);
    TIMING_END(libsodium);

    TIMING_RESULT("Chacha20", SIZE);
}

static int poly1305(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  mono  [  16];
    static u8  sodium[  16];

    TIMING_START(monocypher);
    rename_poly1305_auth(mono, in, SIZE, key);
    TIMING_END(monocypher);

    TIMING_START(libsodium);
    crypto_onetimeauth(sodium, in, SIZE, key);
    TIMING_END(libsodium);

    TIMING_RESULT("Poly1305", 16);
}

static int blake2b(void)
{
    static u8 in    [SIZE];  p_random(in , SIZE);
    static u8 key   [  32];  p_random(key,   32);
    static u8 mono  [  64];
    static u8 sodium[  64];

    TIMING_START(monocypher);
    rename_blake2b_general(mono, 64, key, 32, in, SIZE);
    TIMING_END(monocypher);

    TIMING_START(libsodium);
    crypto_generichash(sodium, 64, in, SIZE, key, 32);
    TIMING_END(libsodium);

    TIMING_RESULT("Blake2b", 64);
}

static int argon2i(void)
{
    size_t    nb_blocks = SIZE / 1024;
    static u8 work_area[SIZE];
    static u8 password [  16];  p_random(password, 32);
    static u8 salt     [  16];  p_random(salt    , 32);
    static u8 mono     [  32];
    static u8 sodium   [  32];

    TIMING_START(monocypher);
    rename_argon2i(mono, 32, work_area, nb_blocks, 3,
                   password, 16, salt, 16, 0, 0, 0, 0);
    TIMING_END(monocypher);

    TIMING_START(libsodium);
    if (crypto_pwhash(sodium, 32, (char*)password, 16, salt,
                      3, nb_blocks * 1024, crypto_pwhash_ALG_DEFAULT)) {
        printf("Libsodium Argon2i failed to execute\n");
    }
    TIMING_END(libsodium);

    TIMING_RESULT("Argon2i", 32);
}

static int x25519(void)
{
    u8 mono_in  [32] = {9};
    u8 mono     [32] = {9};
    u8 sodium_in[32] = {9};
    u8 sodium   [32] = {9};

    TIMING_START(monocypher);
    FOR (i, 0, 250) {
        u8 tmp[32];
        if (rename_x25519(tmp, mono, mono_in)) {
            printf("Monocypher x25519 rejected public key\n");
        }
        FOR (i, 0, 32) { mono_in[i] = mono[i]; }
        FOR (i, 0, 32) { mono   [i] = tmp [i]; }
    }
    TIMING_END(monocypher);

    TIMING_START(libsodium);
    FOR (i, 0, 250) {
        u8 tmp[32];
        if (crypto_scalarmult(tmp, sodium, sodium_in)) {
            printf("Libsodium x25519 rejected public key\n");
        }
        FOR (i, 0, 32) { sodium_in[i] = sodium[i]; }
        FOR (i, 0, 32) { sodium   [i] = tmp   [i]; }
    }
    TIMING_END(libsodium);

    TIMING_RESULT("x25519", 32);
}

static int ed25519(void)
{
    u8 sk       [32];   p_random(sk, 32);
    u8 sk_sodium[64];
    u8 pk       [64];
    crypto_sign_seed_keypair(pk, sk_sodium, sk);

    u8 mono_in  [64] = {9};
    u8 sodium_in[64] = {9};
    u8 mono     [64];
    u8 sodium   [64];

    TIMING_START(monocypher);
    FOR (i, 0, 250) {
        rename_sign(mono, sk, pk, mono_in, 64);
        FOR (i, 0, 64) { mono_in[i] = mono[i]; }
    }
    TIMING_END(monocypher);

    TIMING_START(libsodium);
    FOR (i, 0, 250) {
        crypto_sign_detached(sodium, 0, sodium_in, 64, sk_sodium);
        FOR (i, 0, 64) { sodium_in[i] = sodium[i]; }
    }
    TIMING_END(libsodium);

    TIMING_RESULT("ed25519", 64);
}

static int ed_check(void)
{
    u8 sk       [32];  p_random(sk, 32);
    u8 sk_sodium[64];
    u8 pk       [64];
    crypto_sign_seed_keypair(pk, sk_sodium, sk);

    u8 input    [64];  p_random(input, 32);
    u8 mono     [1] = {0};
    u8 sodium   [1] = {0};

    TIMING_START(monocypher);
    FOR (i, 0, 250) {
        if (rename_check(input, pk, input, 64)) {
            mono[0]++;
        }
    }
    TIMING_END(monocypher);

    TIMING_START(libsodium);
    FOR (i, 0, 250) {
        if (crypto_sign_verify_detached(input, input, 64, pk)) {
            sodium[0]++;
        }
    }
    TIMING_END(libsodium);

    TIMING_RESULT("ed_check", 1);
}

static void print(const char *name, int result)
{
    printf("%s: ", name);
    if (result == 100) {
        printf("As fast as Libsodium\n");
    } else if (result <  100) {
        printf("%d%% slower than Libsodium\n" , 100 - result);
    }
    else {
        printf("%d%% FASTER than Libsodium!!\n", result - 100);
    }
}


int main()
{
    print("Chacha20", chacha20());
    print("Poly1305", poly1305());
    print("Blake2b ", blake2b ());
    print("Argon2i ", argon2i ());
    print("x25519  ", x25519  ());
    print("ed25519 ", ed25519 ());
    print("ed_check", ed_check());
    return 0;
}
