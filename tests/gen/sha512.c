#include <sodium.h>
#include "utils.h"

int main(void)
{
    if (sodium_init() == -1) {
        printf("Libsodium init failed.  Abort.  No test performed\n");
        return 1;
    }

    u8  key[32], nonce[8], in[256], sodium[256];
    FOR (size, 0, 256) {
        FOR(i, 0, 10) {
            p_random(key  ,   32);  print_vector(key  ,   32);
            p_random(nonce,    8);  print_vector(nonce,    8);
            p_random(in   , size);  print_vector(in   , size);
            u64 ctr = rand64();
            crypto_stream_chacha20_xor_ic(sodium, in, size, nonce, ctr, key);
        }
    }
    return 0;
}
