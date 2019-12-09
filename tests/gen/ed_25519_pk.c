#include <sodium.h>
#include "utils.h"

static void test(u8 seed[32])
{
    u8 pk[32];
    u8 sk[64];
    crypto_sign_seed_keypair(pk, sk, seed);
    print_vector(sk, 32);
    print_vector(pk, 32);
}

int main(void)
{
    SODIUM_INIT;
    // random secret keys
    FOR (msg_size, 0, 256) {
        RANDOM_INPUT(sk,  32);
        test(sk);
    }
    // zero secret key
    u8 sk[32] = {0};
    test(sk);

    return 0;
}
