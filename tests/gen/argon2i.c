#include <sodium.h>
#include "utils.h"

void test(size_t nb_blocks, size_t hash_size, size_t nb_iterations)
{
    RANDOM_INPUT(password, 16                     );
    RANDOM_INPUT(salt    , crypto_pwhash_SALTBYTES);
    u8 hash[256];

    if (crypto_pwhash(hash, hash_size, (char*)password, 16, salt,
                      nb_iterations, nb_blocks * 1024,
                      crypto_pwhash_ALG_ARGON2I13)) {
        fprintf(stderr, "Argon2i failed.  "
                "nb_blocks = %lu, "
                "hash_size = %lu "
                "nb_iterations = %lu\n",
                nb_blocks, hash_size, nb_iterations);
        printf(":deadbeef:\n"); // prints a canary to fail subsequent tests
    }

    print_number(nb_blocks                        );
    print_number(nb_iterations                    );
    print_vector(password, 16                     );
    print_vector(salt    , crypto_pwhash_SALTBYTES);
    printf(":\n:\n"); // no key, no additionnal data
    print_vector(hash    , hash_size              );
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    FOR (nb_blocks    , 508, 516) { test(nb_blocks, 32       , 3            ); }
    FOR (hash_size    ,  63,  65) { test(8        , hash_size, 3            ); }
    FOR (nb_iterations,   3,   6) { test(8        , 32       , nb_iterations); }
    return 0;
}
