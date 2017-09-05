#include <sodium.h>
#include "utils.h"

void test(size_t nb_blocks, size_t hash_size)
{
    const size_t salt_size = crypto_pwhash_SALTBYTES;
    RANDOM_INPUT(password, 16       );
    RANDOM_INPUT(salt    , salt_size);
    u8 hash[256];

    if (crypto_pwhash(hash, hash_size, (char*)password, 16, salt,
                      3, nb_blocks * 1024, crypto_pwhash_ALG_DEFAULT)) {
        fprintf(stderr, "Argon2i failed.  nb_blocks = %lu, hash_size =%lu\n",
                nb_blocks, hash_size);
        printf(":deadbeef:\n"); // prints a canary to fail subsequent tests
    }

    print_vector(password, 16);
    print_vector(salt, salt_size);
    print_number(nb_blocks);
    print_vector(hash, hash_size);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    FOR (nb_blocks,  8, 1024) { test(nb_blocks, 32       ); }
    FOR (hash_size, 16,  256) { test(8        , hash_size); }
    return 0;
}
