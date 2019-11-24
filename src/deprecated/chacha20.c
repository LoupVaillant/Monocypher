// Deprecated incremental API for Chacha20
//
// This file *temporarily* provides compatibility with Monocypher 2.x.
// Do not rely on its continued existence.
//
// Deprecated in     : 3.0.0
// Will be removed in: 4.0.0
//
// Deprecated functions & types:
//     crypto_chacha_ctx
//     crypto_chacha20_H
//     crypto_chacha20_init
//     crypto_chacha20_x_init
//     crypto_chacha20_set_ctr
//     crypto_chacha20_encrypt
//     crypto_chacha20_stream
//
// For existing deployments that can no longer be updated or modified,
// use the 2.x family, which will receive security updates until 2024.
//
// Upgrade strategy:
// The new 3.x API can emulate incremental capabilities by setting a
// custom counter.  Make sure you authenticate each chunk before you
// decrypt them, though.

#include "chacha20.h"
#include "monocypher.h"

#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define WIPE_CTX(ctx)              crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)        crypto_wipe(buffer, sizeof(buffer))
#define MIN(a, b)                  ((a) <= (b) ? (a) : (b))
#define MAX(a, b)                  ((a) >= (b) ? (a) : (b))
#define ALIGN(x, block_size)       ((~(x) + 1) & ((block_size) - 1))
typedef int8_t   i8;
typedef uint8_t  u8;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

void crypto_chacha20_H(u8 out[32], const u8 key[32], const u8 in[16])
{
    crypto_hchacha20(out, key, in);
}

void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                          const u8 key[32], const u8 nonce[8])
{
    FOR (i, 0, 32) { ctx->key  [i] = key  [i]; }
    FOR (i, 0,  8) { ctx->nonce[i] = nonce[i]; }
    crypto_chacha20_set_ctr(ctx, 0);
}

void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                            const u8 key[32], const u8 nonce[24])
{
    crypto_hchacha20(ctx->key, key, nonce);
    FOR (i, 0,  8) { ctx->nonce[i] = nonce[i + 16]; }
    crypto_chacha20_set_ctr(ctx, 0);
}

void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, u64 ctr)
{
    ctx->ctr = ctr;
    ctx->pool_idx = 64; // The random pool (re)starts empty
}

void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx, u8 *cipher_text,
                             const u8 *plain_text, size_t text_size)
{
    FOR (i, 0, text_size) {
        if (ctx->pool_idx == 64) {
            crypto_chacha20_ctr(ctx->pool, 0, 64,
                                ctx->key, ctx-> nonce, ctx->ctr);
            ctx->pool_idx = 0;
            ctx->ctr++;
        }
        u8 plain = 0;
        if (plain_text != 0) {
            plain = *plain_text;
            plain_text++;
        }
        *cipher_text = ctx->pool[ctx->pool_idx] ^ plain;
        ctx->pool_idx++;
        cipher_text++;
    }
}

void crypto_chacha20_stream(crypto_chacha_ctx *ctx, u8 *stream, size_t size)
{
    crypto_chacha20_encrypt(ctx, stream, 0, size);
}
