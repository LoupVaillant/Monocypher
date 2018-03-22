#include <sodium.h>
#include "utils.h"

void test(size_t size)
{
    RANDOM_INPUT(key, 32);
    RANDOM_INPUT(in , 32);
    u8 tag[ 16];

    crypto_onetimeauth(tag, in, size, key);

    print_vector(key,   32);
    print_vector(in , size);
    print_vector(tag,   16);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    FOR (size, 0, 32) { test(size); }
    return 0;
}
