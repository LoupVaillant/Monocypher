#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "sha512.h"
#include "utils.h"

typedef struct timespec timespec;

// TODO: provide a user defined buffer size
#define SIZE (1024 * 1024)

// TODO: provide a Mb/s absolute speed
speed_t speed(timespec ref, timespec t)
{
    u64 ref_u = ref.tv_sec * 1000000000 + ref.tv_nsec;
    u64 t_u   = t  .tv_sec * 1000000000 + t  .tv_nsec;
    speed_t s;
    s.ratio = (100 * ref_u) / t_u; // assuming t_u is never zero
    s.time  = t_u ;
    s.ref   = ref_u ;
    return s;
}

static void print(const char *name, speed_t result, const char *lib_name)
{
    printf("%s: %4d Mb/s vs %4d Mb/s\n", name,
           1000000 / result.time,
           1000000 / result.ref);
}

// TODO: adjust this crap
#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START                            \
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
    if (crypto_memcmp(mono, sodium, result_size) != 0) {          \
        printf(name " benchmark failed (different results)\n");   \
    }                                                             \
    return speed(libsodium, monocypher)


static speed_t chacha20(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  nonce [   8];  p_random(nonce,    8);
    static u8  mono  [SIZE];

    TIMING_START {
        crypto_chacha_ctx ctx;
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_encrypt(&ctx, mono, in, SIZE);
    }
    TIMING_END;
}

static speed_t poly1305(void)
{
    static u8  in    [SIZE];  p_random(in   , SIZE);
    static u8  key   [  32];  p_random(key  ,   32);
    static u8  mono  [  16];

    TIMING_START {
        crypto_poly1305_auth(mono, in, SIZE, key);
    }
    TIMING_END;
}

static speed_t blake2b(void)
{
    static u8 in    [SIZE];  p_random(in , SIZE);
    static u8 key   [  32];  p_random(key,   32);
    static u8 mono  [  64];

    TIMING_START(monocypher) {
        crypto_blake2b_general(mono, 64, key, 32, in, SIZE);
    }
    TIMING_END;
}

// TODO: don't just rely on SIZE, add a HARDNESS parameter
static speed_t argon2i(void)
{
    size_t    nb_blocks = SIZE / 1024;
    static u8 work_area[SIZE];
    static u8 password [  16];  p_random(password, 16);
    static u8 salt     [  16];  p_random(salt    , 16);
    static u8 mono     [  32];

    TIMING_START {
        crypto_argon2i(mono, 32, work_area, nb_blocks, 3,
                       password, 16, salt, 16, 0, 0, 0, 0);
    }
    TIMING_END;
}

// TODO: change TIMING_END to print scalarmult per second
static speed_t x25519(void)
{
    u8 mono_in  [32] = {9};
    u8 mono     [32] = {9};

    TIMING_START {
        if (crypto_x25519(mono, mono, mono_in)) {
            printf("Monocypher x25519 rejected public key\n");
        }
    }
    TIMING_END;
}

// TODO: change TIMING_END to print signature/check per second
static void ed25519(void)
{
    u8 sk       [32];   p_random(sk, 32);
    u8 pk       [64];
    crypto_sign_seed_keypair(pk, sk_sodium, sk);

    u8 message   [64];  p_random(message, 64);
    u8 mono_sig  [64];

    // Signature speed
    TIMING_START {
        crypto_sign(mono_sig, sk, pk, message, 64);
    }
    TIMING_END;

    // Verification speed (for correct signatures)
    TIMING_START(monocypher_chk) {
        if (crypto_check(mono_sig, pk, message, 64)) {
            printf("Monocypher verification failed\n");
        }
    }
    TIMING_END;
}

int main()
{
    chacha20();
    poly1305();
    blake2b();
    argon2i();
    x25519();
    ed25519();

    printf("\n");
    return 0;
}
