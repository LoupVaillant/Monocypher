#include "utils.h"
#include "monocypher.h"
#include "stdio.h"

static void store64_le(u8 out[8], u64 in)
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
    out[4] = (in >> 32) & 0xff;
    out[5] = (in >> 40) & 0xff;
    out[6] = (in >> 48) & 0xff;
    out[7] = (in >> 56) & 0xff;
}

u64 load64_le(const u8 s[8])
{
    return (u64)s[0]
        | ((u64)s[1] <<  8)
        | ((u64)s[2] << 16)
        | ((u64)s[3] << 24)
        | ((u64)s[4] << 32)
        | ((u64)s[5] << 40)
        | ((u64)s[6] << 48)
        | ((u64)s[7] << 56);
}

// Deterministic "random" number generator, so we can make "random", yet
// reproducible tests.  To change the random stream, change the seed.
void p_random(u8 *stream, size_t size)
{
    static crypto_chacha_ctx ctx;
    static int is_init = 0;
    if (!is_init) {
        static const u8 seed[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        crypto_chacha20_init(&ctx, seed, seed);
        is_init = 1;
    }
    crypto_chacha20_stream(&ctx, stream, size);
}

// Random 64 bit number
u64 rand64()
{
    u8  tmp;
    u64 result = 0;
    FOR (i, 0, 8) {
        p_random(&tmp, 1);
        result <<= 8;
        result  += tmp;
    }
    return result;
}

void print_vector(u8 *buf, size_t size)
{
    FOR (i, 0, size) {
        printf("%x%x", buf[i] >> 4, buf[i] & 0x0f);
    }
    printf(":\n");
}

void print_number(u64 n)
{
    u8 buf[8];
    store64_le(buf, n);
    print_vector(buf, 8);
}
