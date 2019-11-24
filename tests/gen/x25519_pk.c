#include <sodium.h>
#include "utils.h"

static void test(u8 sk[32])
{
    u8 pk[32];
    crypto_scalarmult_base(pk, sk);

    print_vector(sk, 32);
    print_vector(pk, 32);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;

    // random secret keys
    FOR (i, 0, 50) {
        RANDOM_INPUT(sk, 32);
        test(sk);
    }
    // zero secret key
    u8 sk[32] = {0};
    test(sk);

    return 0;
}
