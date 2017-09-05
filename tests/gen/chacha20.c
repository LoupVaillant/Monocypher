#include <sodium.h>
#include "utils.h"

static void test(size_t size, u64 ctr)
{
    RANDOM_INPUT(key  ,  32);
    RANDOM_INPUT(nonce,   8);
    RANDOM_INPUT(in   , 256); // size <= 256
    u8 out  [256];            // size <= 256

    crypto_stream_chacha20_xor_ic(out, in, size, nonce, ctr, key);

    print_vector(key   ,   32);
    print_vector(nonce ,    8);
    print_vector(in    , size);
    print_number(ctr         );
    print_vector(out, size);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    // regular tests
    FOR (size, 0, 256) { test(size, rand64()); }
    // counter overflow (should wrap around)
    test(256, -1);
    test(256, -2);
    test(256, -3);
    return 0;
}
