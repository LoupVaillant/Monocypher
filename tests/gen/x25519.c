#include <sodium.h>
#include "utils.h"

static void test()
{
    RANDOM_INPUT(sk1, 32);
    RANDOM_INPUT(sk2, 32);
    u8 pk1[32], pk2[32], shared[32];

    crypto_scalarmult_base(pk1, sk1);
    crypto_scalarmult_base(pk2, sk2);
    if (crypto_scalarmult(shared, sk1, pk2)) {
        fprintf(stderr, "Libsodium rejected the public key\n");
        printf(":deadbeef:\n"); // prints a canary to fail subsequent tests
    }

    print_vector(sk1   , 32);
    print_vector(pk2   , 32);
    print_vector(shared, 32);
    printf("\n");
    print_vector(sk2   , 32);
    print_vector(pk1   , 32);
    print_vector(shared, 32);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    FOR (i, 0, 50) { test(); }
    return 0;
}
