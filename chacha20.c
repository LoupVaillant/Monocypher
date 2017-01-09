#include "chacha20.h"

/////////////////
/// Utilities ///
/////////////////

static uint32_t
load32_le(const uint8_t s[4])
{
    // Portable, slow way.
    // Only affects initialisation, though.
    return s[0]
        | (s[1] <<  8)
        | (s[2] << 16)
        | (s[3] << 24);
}

static void
store32_le(uint8_t output[4], uint32_t input)
{
    // Portable, slow way.
    output[0] =  input        & 0xff;
    output[1] = (input >>  8) & 0xff;
    output[2] = (input >> 16) & 0xff;
    output[3] = (input >> 24) & 0xff;
}

////////////
/// Core ///
////////////

static void
chacha20_rounds(uint32_t out[16], const uint32_t in[16])
{
    for (int i = 0; i < 16; i++)
        out[i] = in[i];

    for (int i = 0; i < 10; i++) { // 20 rounds, 2 rounds per loop.
#define ROT_L32(x, n) x = (x << n) | (x >> (32 - n))
#define QUARTERROUND(a, b, c, d)           \
        a += b;  d ^= a;  ROT_L32(d, 16);  \
        c += d;  b ^= c;  ROT_L32(b, 12);  \
        a += b;  d ^= a;  ROT_L32(d,  8);  \
        c += d;  b ^= c;  ROT_L32(b,  7)

        QUARTERROUND(out[0], out[4], out[ 8], out[12]); // column 0
        QUARTERROUND(out[1], out[5], out[ 9], out[13]); // column 1
        QUARTERROUND(out[2], out[6], out[10], out[14]); // column 2
        QUARTERROUND(out[3], out[7], out[11], out[15]); // column 3
        QUARTERROUND(out[0], out[5], out[10], out[15]); // diagonal 1
        QUARTERROUND(out[1], out[6], out[11], out[12]); // diagonal 2
        QUARTERROUND(out[2], out[7], out[ 8], out[13]); // diagonal 3
        QUARTERROUND(out[3], out[4], out[ 9], out[14]); // diagonal 4
    }
}

//////////////////////////////
/// Context initialization ///
//////////////////////////////
static void
init_constant(crypto_chacha_ctx *ctx)
{
    ctx->input[0]  = load32_le((uint8_t*)"expa");
    ctx->input[1]  = load32_le((uint8_t*)"nd 3");
    ctx->input[2]  = load32_le((uint8_t*)"2-by");
    ctx->input[3]  = load32_le((uint8_t*)"te k");
}

static void
init_key(crypto_chacha_ctx *ctx, const uint8_t key[32])
{
    for (int i = 0; i < 8; i++)
        ctx->input[i + 4] = load32_le(key + i*4);
}

static void
init_nonce(crypto_chacha_ctx *ctx, const uint8_t nonce[8])
{
    ctx->input[12] = 0; // counter
    ctx->input[13] = 0; // counter
    ctx->input[14] = load32_le(nonce + 0);
    ctx->input[15] = load32_le(nonce + 4);
}

///////////////////
/// Exposed API ///
///////////////////
void
crypto_init_chacha20(crypto_chacha_ctx *ctx,
                     const uint8_t      key[32],
                     const uint8_t      nonce[8])
{
    init_constant(ctx       );
    init_key     (ctx, key  );
    init_nonce   (ctx, nonce);
    ctx->pool_index = 64; // the random pool starts empty
}

void
crypto_init_Xchacha20(crypto_chacha_ctx *ctx,
                      const uint8_t      key[32],
                      const uint8_t      nonce[24])
{
    crypto_chacha_ctx init_ctx;
    init_constant (&init_ctx     );
    init_key      (&init_ctx, key);
    // init big nonce
    for (int i = 0; i < 4; i++)
        init_ctx.input[i + 12] = load32_le(nonce +  i*4);

    init_constant(ctx);
    uint32_t buffer[16];
    chacha20_rounds(buffer, ctx->input);
    // init key
    for (int i = 0; i < 4; i++) {
        ctx->input[i + 4] = buffer[i     ]; // constant
        ctx->input[i + 8] = buffer[i + 12]; // counter and nonce
    }
    init_nonce(ctx, nonce + 16);
    ctx->pool_index = 64; // the random pool starts empty
}

void
crypto_encrypt_chacha20(crypto_chacha_ctx *ctx,
                        const uint8_t     *plain_text,
                        uint8_t           *cipher_text,
                        size_t             msg_length)
{
    for (size_t i = 0; i < msg_length; i++) {
        // refill the pool if empty
        if (ctx->pool_index == 64) {
            // fill the pool
            uint32_t buffer[16];
            chacha20_rounds(buffer, ctx->input);
            for (int i = 0; i < 16; i++)
                store32_le(ctx->random_pool + i*4, buffer[i] + ctx->input[i]);
            // update the counters
            ctx->pool_index = 0;
            ctx->input[12]++;
            if (!ctx->input[12])
                ctx->input[13]++;
        }
        // use the pool for encryption (or random stream)
        cipher_text[i] =
            (plain_text == 0 ? 0 : plain_text[i])
            ^ ctx->random_pool[ctx->pool_index];
        ctx->pool_index++;
    }
}
