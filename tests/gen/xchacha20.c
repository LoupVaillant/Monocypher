#include <sodium.h>
#include "utils.h"

static void test(size_t size, u64 ctr)
{
    RANDOM_INPUT(key  ,  32);
    RANDOM_INPUT(nonce,  24);
    RANDOM_INPUT(in   , 128); // size <= 128
    u8 out  [128];            // size <= 128

    crypto_stream_xchacha20_xor_ic(out, in, size, nonce, ctr, key);

    print_vector(key   ,   32);
    print_vector(nonce ,   24);
    print_vector(in    , size);
    print_number(ctr         );
    print_vector(out, size);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    // regular tests
    FOR (size, 0, 128) { test(size, rand64()); }
    // counter overflow (should wrap around)
    test(128, -1);
    test(128, -2);
    test(128, -3);
    return 0;
}
