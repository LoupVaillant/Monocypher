#include <sodium.h>
#include "utils.h"

static void test(size_t key_size, size_t msg_size)
{
    RANDOM_INPUT(key, 256);
    RANDOM_INPUT(msg, 256);
    u8 tag[64];

    crypto_auth_hmacsha512_state ctx;
    crypto_auth_hmacsha512_init  (&ctx, key, key_size);
    crypto_auth_hmacsha512_update(&ctx, msg, msg_size);
    crypto_auth_hmacsha512_final (&ctx, tag);

    print_vector(key, key_size);
    print_vector(msg, msg_size);
    print_vector(tag,       64);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    FOR (key_size,   0,  32) { test(key_size, 32); }
    FOR (key_size, 120, 136) { test(key_size, 32); }
    FOR (msg_size,   0, 256) { test(32, msg_size); }
    return 0;
}
