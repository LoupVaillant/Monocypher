#include "utils.h"
#include "ed25519.h"

void test(u8 sk[32])
{
    u8 pk[32];
    ed25519_publickey(sk, pk);

    print_vector(sk, 32);
    print_vector(pk, 32);
}

int main(void)
{
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
