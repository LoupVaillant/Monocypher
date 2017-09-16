#include <sodium.h>
#include "utils.h"

void test(size_t size)
{
    RANDOM_INPUT(in  , 256);
    u8 hash[64];

    crypto_hash_sha512(hash, in, size);

    print_vector(in  , size);
    print_vector(hash, 64);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    FOR(size, 0, 256) {
        test(size);
    }
    return 0;
}
