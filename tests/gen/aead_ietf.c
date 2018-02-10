#include <sodium.h>
#include "utils.h"

static void test(size_t text_size, size_t ad_size)
{
    RANDOM_INPUT(key  ,  32);
    RANDOM_INPUT(nonce,  24);
    RANDOM_INPUT(ad   ,  32); // ad size   <=  32
    RANDOM_INPUT(text , 128); // text_size <= 128
    u8 out[16 + 128];         // text_size <= 128

    crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        out + 16, out, 0, text, text_size, ad, ad_size, 0, nonce, key);

    print_vector(key   , 32);
    print_vector(nonce , 24);
    print_vector(ad    , ad_size);
    print_vector(text  , text_size);
    print_vector(out   , text_size + 16);
    printf("\n");
}

int main(void)
{
    SODIUM_INIT;
    // regular tests
    FOR (text_size, 0, 128) { test(text_size, 0); }
    FOR (text_size, 0, 128) { test(text_size, 4); }
    FOR (  ad_size, 0,  32) { test(0,   ad_size); }
    FOR (  ad_size, 0,  32) { test(16,  ad_size); }
    return 0;
}
