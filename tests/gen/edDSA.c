#include <sodium.h>
#include "utils.h"
#include "ed25519.h"

void test(size_t msg_size)
{
    RANDOM_INPUT(sk ,  32);
    RANDOM_INPUT(msg, 256);
    u8 pk[32], sig[64];

    ed25519_publickey(sk, pk);
    ed25519_sign(msg, msg_size, sk, pk, sig);

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
