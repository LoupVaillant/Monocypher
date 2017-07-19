#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include <ed25519.h>

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
typedef  int8_t   i8;
typedef uint8_t   u8;
typedef uint32_t u32;
typedef  int32_t i32;
typedef  int64_t i64;
typedef uint64_t u64;

// Deterministic "random" number generator, so we can make "random", yet
// reproducible tests.  To change the random stream, change the seed.
void p_random(u8 *stream, u8 size)
{
    static crypto_chacha_ctx ctx;
    static int is_init = 0;
    if (!is_init){
        static const u8 seed[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        crypto_chacha20_init(&ctx, seed, seed);
        is_init = 1;
    }
    crypto_chacha20_stream(&ctx, stream, size);
}

int main(void)
{
    u8 sk[32], pk_mono[32], pk_donna[32];
    u8 msg[255], sig_mono[64], sig_donna[64];
    int status = 0;
    FOR (size, 0, 255) {
        // public keys
        p_random(sk, 32);
        crypto_sign_public_key(pk_mono, sk);
        ed25519_publickey(sk, pk_donna);
        status |= crypto_memcmp(pk_mono, pk_donna, 32);
        // signatures
        p_random(msg, size);
        crypto_sign(sig_mono, sk, pk_mono, msg, size);
        ed25519_sign(msg, size, sk, pk_donna, sig_donna);
        status |= crypto_memcmp(sig_mono, sig_donna, 64);
    }
    printf("%s: EdDSA (donna)\n", status != 0 ? "FAILED" : "OK");
    return status;
}
