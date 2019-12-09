#include <sodium.h>
#include "utils.h"

static void test(size_t size, u32 ctr)
{
    RANDOM_INPUT(key  ,  32);
    RANDOM_INPUT(nonce,  12);
    RANDOM_INPUT(in   , 128); // size <= 128
    u8 out[128];              // size <= 128

    crypto_stream_chacha20_ietf_xor_ic(out, in, size, nonce, ctr, key);

    print_vector(key  ,   32);
    print_vector(nonce,   12);
    print_vector(in   , size);
    print_number(ctr        );
    print_vector(out  , size);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    FOR (size, 0, 128) { test(size, (u32)rand64()); }
    return 0;
}
