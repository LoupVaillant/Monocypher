#include <sodium.h>
#include "utils.h"

void test(size_t msg_size)
{
    RANDOM_INPUT(seed,  32);
    RANDOM_INPUT(msg , 256);
    u8 pk[32], sk[64], sig[64];

    crypto_sign_seed_keypair(pk, sk, seed);
    crypto_sign_detached(sig, 0, msg, msg_size, sk);

    print_vector(sk , 32      );
    print_vector(pk , 32      );
    print_vector(msg, msg_size);
    print_vector(sig, 64      );
}

int main(void)
{
    SODIUM_INIT;
    FOR (msg_size, 0, 256) { test(msg_size); }
    return 0;
}
