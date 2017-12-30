#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sodium.h"

// Copied from utils.h
#include <inttypes.h>
#include <stddef.h>
typedef int8_t   i8;
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;
#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)
// end of copy from utils.h

typedef struct timespec timespec;

// TODO: provide a user defined buffer size
#define KILOBYTE 1024
#define MEGABYTE (1024 * KILOBYTE)
#define SIZE     (50 * MEGABYTE)
#define MULT     (SIZE / MEGABYTE)

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

u64 speed(timespec duration)
{
#define DIV 1000 // avoid round errors
    static const u64 giga = 1000000000;
    return DIV * giga / (duration.tv_nsec + duration.tv_sec * giga);
}

static void print(const char *name, u64 speed, const char *unit)
{
    printf("%s: %5" PRIu64 " %s\n", name, speed, unit);
}

// TODO: adjust this crap
#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START                            \
    timespec duration;                          \
    duration.tv_sec = -1;                       \
    duration.tv_nsec = -1;                      \
    duration.tv_sec  = 3600 * 24;               \
    duration.tv_nsec = 0;                       \
    FOR (i, 0, 10) {                            \
        TIMESTAMP(start);

#define TIMING_END                              \
    TIMESTAMP(end);                             \
    duration = min(duration, diff(start, end)); \
    } /* end FOR*/                              \
    return speed(duration)


// not random at all, it's just to measure the speed
void p_random(u8 *buf, size_t size)
{
    static u8 v = 57; // barely random variable
    FOR (i, 0, size) {
        buf[i] = v;
        v *= 57;
    }
}

static u64 chacha20(void)
{
    static u8  in   [SIZE];  p_random(in   , SIZE);
    static u8  key  [  32];  p_random(key  ,   32);
    static u8  nonce[   8];  p_random(nonce,    8);
    static u8  out  [SIZE];

    TIMING_START {
        crypto_stream_chacha20_xor(out, in, SIZE, nonce, key);
    }
    TIMING_END;
}

static u64 poly1305(void)
{
    static u8  in [SIZE];  p_random(in   , SIZE);
    static u8  key[  32];  p_random(key  ,   32);
    static u8  out[  16];

    TIMING_START {
        crypto_onetimeauth(out, in, SIZE, key);
    }
    TIMING_END;
}

static u64 authenticated(void)
{
    static u8  in   [SIZE];  p_random(in   , SIZE);
    static u8  key  [  32];  p_random(key  ,   32);
    static u8  nonce[   8];  p_random(nonce,    8);
    static u8  out  [SIZE];
    static u8  mac  [crypto_aead_xchacha20poly1305_ietf_ABYTES];
    TIMING_START {
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
    }
    TIMING_END;
}

static u64 blake2b(void)
{
    static u8 in  [SIZE];  p_random(in , SIZE);
    static u8 key [  32];  p_random(key,   32);
    static u8 hash[  64];

    TIMING_START {
        crypto_generichash(hash, 64, in, SIZE, key, 32);
    }
    TIMING_END;
}

static u64 argon2i(void)
{
    static u8 password [  16];  p_random(password, 16);
    static u8 salt     [  16];  p_random(salt    , 16);
    static u8 hash     [  32];

    TIMING_START {
        if (crypto_pwhash(hash, 32, (char*)password, 16, salt,
                          3, SIZE, crypto_pwhash_ALG_ARGON2I13)) {
            fprintf(stderr, "Argon2i failed.\n");
        }
    }
    TIMING_END;
}

static u64 x25519(void)
{
    u8 in [32] = {9};
    u8 out[32] = {9};

    TIMING_START {
        if (crypto_scalarmult(out, out, in)) {
            fprintf(stderr, "Libsodium rejected the public key\n");
        }
    }
    TIMING_END;
}

static u64 edDSA_sign(void)
{
    u8 sk       [64];  p_random(sk, 32);
    u8 pk       [32];  crypto_sign_keypair(pk, sk);
    u8 message  [64];  p_random(message, 64);
    u8 signature[64];

    TIMING_START {
        crypto_sign_detached(signature, 0, message, 64, sk);
    }
    TIMING_END;
}

static u64 edDSA_check(void)
{
    u8 sk       [64];  p_random(sk, 32);
    u8 pk       [32];  crypto_sign_keypair(pk, sk);
    u8 message  [64];  p_random(message, 64);
    u8 signature[64];

    crypto_sign_detached(signature, 0, message, 64, sk);

    TIMING_START {
        if (crypto_sign_verify_detached(signature, message, 64, pk)) {
            printf("Monocypher verification failed\n");
        }
    }
    TIMING_END;
}

int main()
{
    if (sodium_init() == -1) {
        printf("Libsodium init failed.  Abort.\n");
        return 1;
    }
    print("Chacha20         ", chacha20()      * MULT/DIV, "Mb/s"            );
    print("Poly1305         ", poly1305()      * MULT/DIV, "Mb/s"            );
    print("Auth'd encryption", authenticated() * MULT/DIV, "Mb/s"            );
    print("Blake2b          ", blake2b()       * MULT/DIV, "Mb/s"            );
    print("Argon2i          ", argon2i()       * MULT/DIV, "Mb/s (3 passes)" );
    print("x25519           ", x25519()        / DIV, "exchanges  per second");
    print("EdDSA(sign)      ", edDSA_sign()    / DIV, "signatures per second");
    print("EdDSA(check)     ", edDSA_check()   / DIV, "checks     per second");
    printf("\n");
    return 0;
}
