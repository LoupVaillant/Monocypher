#include <stdio.h>
#include "blake2b.h"

int main()
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx);
    uint8_t input[128];
    for (unsigned i = 0; i < 128; i++) {
        input[i] = i;
    }
    for (unsigned i = 0; i < 5000000; i++) {
        crypto_blake2b_update(&ctx, input, 128);

    }
    return 0;
}
