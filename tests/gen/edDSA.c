#include <sodium.h>
#include "utils.h"
#include "ed25519.h"

void test(size_t size)
{
    RANDOM_INPUT(sk ,  32);
    RANDOM_INPUT(msg, 256);
    u8 pk[32], sig[64];

    ed25519_publickey(sk, pk);
    ed25519_sign(msg, size, sk, pk, sig);

    print_vector(sk , 32  );
    print_vector(msg, size);
    print_vector(sig, 64  );
}

int main(void)
{
    SODIUM_INIT;
    FOR (i, 0, 256) { test(i); }
    return 0;
}
