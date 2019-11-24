#include <sodium.h>
#include "utils.h"

static void test(size_t size, size_t key_size, size_t hash_size)
{
    RANDOM_INPUT(in  , 256);
    RANDOM_INPUT(key , 32);
    u8 hash[64];

    crypto_generichash(hash, hash_size, in, size, key, key_size);

    print_vector(in  , size);
    print_vector(key , key_size);
    print_vector(hash, hash_size);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    FOR(size     , 0, 256) { test(size, 0       , 64       ); }
    FOR(key_size , 0,  32) { test(128 , key_size, 64       ); }
    FOR(hash_size, 1,  64) { test(128 , 0       , hash_size); }
    return 0;
}
