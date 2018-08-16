#include <sodium.h>
#include "utils.h"

int main(void)
{
    SODIUM_INIT;

    FOR (size, 0, 50) {
        RANDOM_INPUT(key  , 32);
        RANDOM_INPUT(in   , 16);
        u8 out[32];

        crypto_core_hchacha20(out, in, key, 0);

        print_vector(key   , 32);
        print_vector(in    , 16);
        print_vector(out   , 32);
        printf("\n");
    }

    return 0;
}
