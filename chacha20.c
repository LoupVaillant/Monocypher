#include "chacha20.h"
#include <string.h>

/////////////////
/// Utilities ///
/////////////////

// undefined if n >= 32 or n == 0
// Should compile into a single rot32 instruction
// if available on the processsor.
static uint32_t
rotl32 (uint32_t x, uint32_t n)
{
    return (x << n) | (x >> (32 - n));
}

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

// The counter is basically unlimited.  Still, if you ever allow
// it to wrap around itself (by encrypting  more than 2^70 bytes
// per nonce), you'll expose the XOR of the begining and the end
// of your plaintext, and lose confidentiality in the process.
// Oops.
static void
increment_counter(crypto_chacha_ctx *ctx)
{
    ctx->input[12]++;
    // That conditional ultimately only depends on the length of the input,
    // which is not secret.  Heck, the counter itself is not secret.
    // No timing attack there, we're fine.
    if (!ctx->input[12])
        ctx->input[13]++;
}

///////////////////////
/// Round functions ///
///////////////////////

// A quarter round is meant to mangle a fourth of a chacha context.
// (a line, a column, or any subset you can think of).  Enough of
// these rounds, carefully chosen, will garble the input beyond
// recognition.
//
// WARNING: THIS OPERATION IS REVERSIBLE.
//
// If you build a crypto primitive on top of it without additional
// precautions, any rookie cryptanalist can break it.
#define QUARTERROUND(a, b, c, d)       \
    a = a + b;  d = rotl32(d ^ a, 16); \
    c = c + d;  b = rotl32(b ^ c, 12); \
    a = a + b;  d = rotl32(d ^ a,  8); \
    c = c + d;  b = rotl32(b ^ c,  7)

// Mangles the chacha context into a pseudorandom output
// That is, if you don't know the key stored in the context,
// you can't deduce squat about the output.  This is true
// even if you know the output of many other contexes, even
// if they differ from this one by only one bit.
static void
chacha20_rounds(uint8_t output[64], const crypto_chacha_ctx *ctx)
{
    // Local variables instead of indices, to facilitate optimisations
    // TODO: test this shit.  The speed increase might be small.
    uint32_t x0  = ctx->input[ 0];
    uint32_t x1  = ctx->input[ 1];
    uint32_t x2  = ctx->input[ 2];
    uint32_t x3  = ctx->input[ 3];
    uint32_t x4  = ctx->input[ 4];
    uint32_t x5  = ctx->input[ 5];
    uint32_t x6  = ctx->input[ 6];
    uint32_t x7  = ctx->input[ 7];
    uint32_t x8  = ctx->input[ 8];
    uint32_t x9  = ctx->input[ 9];
    uint32_t x10 = ctx->input[10];
    uint32_t x11 = ctx->input[11];
    uint32_t x12 = ctx->input[12];
    uint32_t x13 = ctx->input[13];
    uint32_t x14 = ctx->input[14];
    uint32_t x15 = ctx->input[15];

    for (int i = 20; i > 0; i -= 2) { // 20 rounds, 2 rounds per loop.
        // The ctx is viewed as a matrix, whose indices are like
        //  0  1  2  3
        //  4  5  6  7
        //  8  9 10 11
        // 12 13 14 15

        // Column round.  Very SIMD friendly, if you want high performance.
        QUARTERROUND(x0, x4,  x8, x12); // column 0
        QUARTERROUND(x1, x5,  x9, x13); // column 1
        QUARTERROUND(x2, x6, x10, x14); // column 2
        QUARTERROUND(x3, x7, x11, x15); // column 3

        // South East diagonal round.
        // With a bit of permutation, this is also very SIMD friendly.
        QUARTERROUND(x0, x5, x10, x15); // diagonal 1
        QUARTERROUND(x1, x6, x11, x12); // diagonal 2
        QUARTERROUND(x2, x7,  x8, x13); // diagonal 3
        QUARTERROUND(x3, x4,  x9, x14); // diagonal 4
    }

    // Now our buffer is seriously garbled.  However, it is still easy
    // to deduce the initial context from it: just invert the quarter
    // rounds and apply that in reverse order.
    //
    // So we perform a final operation: we add the initial context to
    // the buffer.  Half of this initial context is made up of the key,
    // unknown to the attacker (the constant, nonce and counter are
    // known however).
    //
    // This effectively removes half the intel the attacker needs to
    // reverse the computation, forcing him to try all 2^256 possibilities.
    // Well that's the idea anyway.  the security of  this trick is not
    // proven, and with few enough rounds, there are clever schemes that
    // don't try the whole key space.
    //
    // As of 2016, "low enough" means 6 or 7 rounds.  We use 20.
    // This shoul be enough to prevent anyone from breaking them all
    // in the forseeable future.
    //
    // Note that in principle, we don't have to add the constants nonce
    // and counter: that part could be reversed by the attacker anyway
    // so we'd be just as secure if we didn't.  However that only improves
    // the performance of naive implementations such as this one.  With
    // SIMD, it's faster to just add the lot, so that's what the standard
    // does.
    x0  += ctx->input[ 0];
    x1  += ctx->input[ 1];
    x2  += ctx->input[ 2];
    x3  += ctx->input[ 3];
    x4  += ctx->input[ 4];
    x5  += ctx->input[ 5];
    x6  += ctx->input[ 6];
    x7  += ctx->input[ 7];
    x8  += ctx->input[ 8];
    x9  += ctx->input[ 9];
    x10 += ctx->input[10];
    x11 += ctx->input[11];
    x12 += ctx->input[12];
    x13 += ctx->input[13];
    x14 += ctx->input[14];
    x15 += ctx->input[15];

    // finally, we can output our buffer
    store32_le(output +  0, x0 );
    store32_le(output +  4, x1 );
    store32_le(output +  8, x2 );
    store32_le(output + 12, x3 );
    store32_le(output + 16, x4 );
    store32_le(output + 20, x5 );
    store32_le(output + 24, x6 );
    store32_le(output + 28, x7 );
    store32_le(output + 32, x8 );
    store32_le(output + 36, x9 );
    store32_le(output + 40, x10);
    store32_le(output + 44, x11);
    store32_le(output + 48, x12);
    store32_le(output + 52, x13);
    store32_le(output + 56, x14);
    store32_le(output + 60, x15);
}

// This one is the same as chacha20_rounds, only it gives you only
// half the output (256 bytes). It's basically the same as HSalsa20,
// except build on ChaCha.  It is provably as secure as ChaCha20
static void
half_chacha20_rounds(uint32_t output[8], const crypto_chacha_ctx *ctx)
{
    // Copy pasta rom chacha20_rounds
    uint32_t x0  = ctx->input[ 0];
    uint32_t x1  = ctx->input[ 1];
    uint32_t x2  = ctx->input[ 2];
    uint32_t x3  = ctx->input[ 3];
    uint32_t x4  = ctx->input[ 4];
    uint32_t x5  = ctx->input[ 5];
    uint32_t x6  = ctx->input[ 6];
    uint32_t x7  = ctx->input[ 7];
    uint32_t x8  = ctx->input[ 8];
    uint32_t x9  = ctx->input[ 9];
    uint32_t x10 = ctx->input[10];
    uint32_t x11 = ctx->input[11];
    uint32_t x12 = ctx->input[12];
    uint32_t x13 = ctx->input[13];
    uint32_t x14 = ctx->input[14];
    uint32_t x15 = ctx->input[15];

    // Copy pasta rom chacha20_rounds
    for (int i = 20; i > 0; i -= 2) {
        QUARTERROUND(x0, x4,  x8, x12); // column 0
        QUARTERROUND(x1, x5,  x9, x13); // column 1
        QUARTERROUND(x2, x6, x10, x14); // column 2
        QUARTERROUND(x3, x7, x11, x15); // column 3
        QUARTERROUND(x0, x5, x10, x15); // diagonal 1
        QUARTERROUND(x1, x6, x11, x12); // diagonal 2
        QUARTERROUND(x2, x7,  x8, x13); // diagonal 3
        QUARTERROUND(x3, x4,  x9, x14); // diagonal 4
    }

    // Okay, remember about needing that addition?  Well, we only
    // Disclose half of the output, and that ensures the attacker
    // is missing 256 bits of information just like in regular chacha20.
    //
    // However, to be able to *prove* this is just as secure as chacha20,
    // we will copy the numbers we know the attacker could have deduced
    // anyway.  That is:
    // - words 0, 1, 2, 3 (chacha constant),
    // - words 12 and 13  (counter),
    // - words 14 and 15  (nonce)
    //
    // This lets us avoid a couple additional loads and additions,
    // for even moar speed.
    output[0] = ctx->input[ 0]; // don't add the constant
    output[1] = ctx->input[ 1]; // don't add the constant
    output[2] = ctx->input[ 2]; // don't add the constant
    output[3] = ctx->input[ 3]; // don't add the constant
    output[4] = ctx->input[12]; // don't add the counter
    output[5] = ctx->input[13]; // don't add the counter
    output[6] = ctx->input[14]; // don't add the nonce
    output[7] = ctx->input[15]; // don't add the nonce
}

//////////////////////////////
/// Context initialization ///
//////////////////////////////
static void
init_constant(crypto_chacha_ctx *ctx)
{
    // This constant looks like wasted space, that could be used
    // for a larger key, nounce, or counter.  But while its exact
    // value hardly matters, some properties it has do.
    //
    // Among other things, this constant prevents the existence of
    // the all zero context, which would map to an all zero output;
    // and is "assymetric" enough to guarantee good mangling.
    //
    // Also, the very exstence of a constant reduces reduces the amount
    // of the context that's under the control of the attacker (a fourth
    // instead of a whole half).
    //
    // Simply put: keep the constant, it's safer that way.
    ctx->input[0]  = load32_le((uint8_t*)"expa");
    ctx->input[1]  = load32_le((uint8_t*)"nd 3");
    ctx->input[2]  = load32_le((uint8_t*)"2-by");
    ctx->input[3]  = load32_le((uint8_t*)"te k");
}

static void
init_key(crypto_chacha_ctx *ctx, const uint8_t key[32])
{
    ctx->input[4]  = load32_le(key +  0);
    ctx->input[5]  = load32_le(key +  4);
    ctx->input[6]  = load32_le(key +  8);
    ctx->input[7]  = load32_le(key + 12);
    ctx->input[8]  = load32_le(key + 16);
    ctx->input[9]  = load32_le(key + 20);
    ctx->input[10] = load32_le(key + 24);
    ctx->input[11] = load32_le(key + 28);
}

static void
init_ctr(crypto_chacha_ctx *ctx, uint64_t ctr)
{
    ctx->input[12] = (uint32_t) ctr;                   // LSB
    ctx->input[13] = (uint32_t) (ctr >> (uint64_t)32); // MSB
}

static void
init_nonce(crypto_chacha_ctx *ctx, const uint8_t nonce[8])
{
    ctx->input[14] = load32_le(nonce + 0);
    ctx->input[15] = load32_le(nonce + 4);
}

static void
init_big_nonce(crypto_chacha_ctx *ctx, const uint8_t nonce[16])
{
    ctx->input[12] = load32_le(nonce +  0);
    ctx->input[13] = load32_le(nonce +  4);
    ctx->input[14] = load32_le(nonce +  8);
    ctx->input[15] = load32_le(nonce + 12);
}

static void
init_chacha20(crypto_chacha_ctx *ctx,
              const uint8_t      key[32],
              const uint8_t      nonce[8],
              uint64_t           ctr)
{
    init_constant(ctx       );
    init_key     (ctx, key  );
    init_ctr     (ctx, ctr  );
    init_nonce   (ctx, nonce);
}

// Initializes a chacha context, with a bigger nonce.
//
// It uses a cascade scheme where a first block is initialised with
// the first 128 bits of the nounce (and no counter), and a second block
// is initialised with a derived key from the first block, and the
// last 64 bits of the nonce.
//
// It's slower than regular initialization, but that big nonce can now
// be selected at random without fear of collision.
static void
init_Xchacha20(crypto_chacha_ctx *ctx,
               const uint8_t      key[32],
               const uint8_t      nonce[24],
               uint64_t           ctr)
{
    // initialise a first block
    crypto_chacha_ctx init_ctx;
    init_constant (&init_ctx       );
    init_key      (&init_ctx, key  );
    init_big_nonce(&init_ctx, nonce);

    // set up the cascade
    init_constant(ctx            );
    init_ctr     (ctx, ctr       );
    init_nonce   (ctx, nonce + 16);
    half_chacha20_rounds(ctx->input + 5, &init_ctx); // init derived key
}

static void
encrypt_chacha20(crypto_chacha_ctx *ctx,
                 const uint8_t     *plain_text,
                 uint8_t           *cipher_text,
                 size_t             msg_length)
{
    size_t remaining_bytes = msg_length;
    for (;;) {
        uint8_t random_block[64];
        chacha20_rounds(random_block, ctx);
        increment_counter(ctx); // the only modification of the context

        // XOR the last pseudo-random block with the input,
        // then end the loop.
        if (remaining_bytes <= 64) {
            for (unsigned i = 0; i < remaining_bytes; i++)
                cipher_text[i] = plain_text[i] ^ random_block[i];
            return;
        }

        // XOR the current pseudo-random block with the input.
        for (int i = 0; i < 64; i++)
            cipher_text[i] = plain_text[i] ^ random_block[i];
        remaining_bytes -= 64;
        cipher_text     += 64;
        plain_text      += 64;
    }
}

//////////////////
/// Encryption ///
//////////////////
void
crypto_encrypt_chacha20(const uint8_t  key[32],
                        const uint8_t  nonce[8],
                        uint64_t       ctr,
                        const uint8_t *plain_text,
                        uint8_t       *cipher_text,
                        size_t         msg_length)
{
    crypto_chacha_ctx ctx;
    init_chacha20(&ctx, key, nonce, ctr);
    encrypt_chacha20(&ctx, plain_text, cipher_text, msg_length);
}


void
crypto_encrypt_Xchacha20(const uint8_t  key[32],
                         const uint8_t  nonce[24],
                         uint64_t       ctr,
                         const uint8_t *plain_text,
                         uint8_t       *cipher_text,
                         size_t         msg_length)
{
    crypto_chacha_ctx ctx;
    init_Xchacha20(&ctx, key, nonce, ctr);
    encrypt_chacha20(&ctx, plain_text, cipher_text, msg_length);
}

void
crypto_block_chacha20(const uint8_t key[32],
                      const uint8_t nonce[8],
                      uint64_t      ctr,
                      uint8_t       output[64])
{
    crypto_chacha_ctx ctx;
    init_chacha20(&ctx, key, nonce, ctr);
    chacha20_rounds(output, &ctx);
}

void
crypto_block_Xchacha20(const uint8_t key[32],
                       const uint8_t nonce[24],
                       uint64_t      ctr,
                       uint8_t       output[64])
{
    crypto_chacha_ctx ctx;
    init_Xchacha20(&ctx, key, nonce, ctr);
    chacha20_rounds(output, &ctx);
}

///////////////////////////////
/// Random number generator ///
///////////////////////////////
void
crypto_init_rng(crypto_rng_context *ctx,
                const uint8_t       key[32],
                const uint8_t       nonce[8])
{
    init_chacha20(&ctx->chacha_ctx, key, nonce, 0);
    ctx->remaining_bytes = 0;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void
crypto_random_bytes(crypto_rng_context *ctx,
                    uint8_t            *out,
                    size_t              nb_bytes)
{
    // Consume any remaining byte from a previous
    // call to random_bytes
    size_t penultimate_size = MIN(nb_bytes, ctx->remaining_bytes);
    memcpy(out, ctx->reminder + 64 - ctx->remaining_bytes, penultimate_size);
    out                  += penultimate_size;
    nb_bytes             -= penultimate_size;
    ctx->remaining_bytes -= penultimate_size;

    if (nb_bytes == 0) { return ;} // past that point, ctx->remaining_bytes is 0

    // fill the output stream block by block
    while (nb_bytes >= 64) {
        chacha20_rounds(out, &ctx->chacha_ctx);
        increment_counter(&ctx->chacha_ctx);
        out      += 64;
        nb_bytes -= 64;
    }

    // Generate one last block and finish this
    chacha20_rounds(ctx->reminder, &ctx->chacha_ctx); // there was no reminder
    increment_counter(&ctx->chacha_ctx);
    memcpy(out, ctx->reminder, nb_bytes); // those two lines work even
    ctx->remaining_bytes = 64 - nb_bytes; // when nb_bytes is already 0
}
