#include "argon2i.h"
#include "blake2b.h"

static uint64_t
load64_le(const uint8_t s[8])
{
    // Portable, slow way
    return (uint64_t)s[0]
        | ((uint64_t)s[1] <<  8)
        | ((uint64_t)s[2] << 16)
        | ((uint64_t)s[3] << 24)
        | ((uint64_t)s[4] << 32)
        | ((uint64_t)s[5] << 40)
        | ((uint64_t)s[6] << 48)
        | ((uint64_t)s[7] << 56);
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

static void
store64_le(uint8_t output[8], uint64_t input)
{
    // Portable, slow way.
    output[0] =  input        & 0xff;
    output[1] = (input >>  8) & 0xff;
    output[2] = (input >> 16) & 0xff;
    output[3] = (input >> 24) & 0xff;
    output[4] = (input >> 32) & 0xff;
    output[5] = (input >> 40) & 0xff;
    output[6] = (input >> 48) & 0xff;
    output[7] = (input >> 56) & 0xff;
}

static uint64_t
rotr64(uint64_t x, uint64_t y)
{
    return (x >> y) ^ (x << (64 - y));
}

static size_t
min(size_t a, size_t b)
{
    return a <= b ? a : b;
}

typedef struct block {
    uint64_t a[128]; // 1024 octets in 128 64-bit words
} block;

static void
zero_block(block *b)
{
    for (int i = 0; i < 128; i++) {
        b->a[i] = 0;
    }
}

static void
load_block(block *b, const uint8_t bytes[1024])
{
    for (int i = 0; i < 128; i++) {
        b->a[i] = load64_le(bytes + i * 8);
    }
}

static void
store_block(uint8_t bytes[1024], const block *b)
{
    for (int i = 0; i < 128; i++) {
        store64_le(bytes + i * 8, b->a[i]);
    }
}

static void
copy_block(block *out, const block *in)
{
    for (int i = 0; i < 128; i++) {
        out->a[i] = in->a[i];
    }
}

static void
xor_block(block *out, const block *in)
{
    for (int i = 0; i < 128; i++) {
        out->a[i] ^= in->a[i];
    }
}

static void
extended_hash(uint8_t       *digest, uint32_t digest_size,
              const uint8_t *input , uint32_t input_size)
{
    crypto_blake2b_ctx ctx;
    uint8_t            buf[4];
    store32_le(buf, digest_size);

    crypto_general_blake2b_init(&ctx, min(digest_size, 64), 0, 0);
    crypto_blake2b_update(&ctx, buf, 4);
    crypto_blake2b_update(&ctx, input, input_size);
    crypto_blake2b_final(&ctx, digest);

    if (digest_size > 64) {
        // the conversion to u64 avoids integer overflow on
        // ludicrously big hash sizes.
        uint32_t r   = (((uint64_t)digest_size + 31) / 32) - 2;
        uint32_t i   =  1;
        uint32_t in  =  0;
        uint32_t out = 32;
        while (i <= r) {
            // Input and output overlap.
            // This shouldn't be a problem.
            crypto_blake2b(digest + out, input + in, 64);
            i   +=  1;
            in  += 32;
            out += 32;
        }
        crypto_general_blake2b(digest + out, digest_size - (32 * r), 0, 0,
                               digest + in , 64);
    }
}

// Computes Z from R in place
static void
g_rounds(block *work_block)
{
#define LSB(x) ((x) & 0xffffffff)
#define G(a, b, c, d)                                           \
    a += b + 2 * LSB(a) * LSB(b);  d = rotr64(d ^ a, 32);       \
    c += d + 2 * LSB(c) * LSB(d);  b = rotr64(b ^ c, 24);       \
    a += b + 2 * LSB(a) * LSB(b);  d = rotr64(d ^ a, 16);       \
    c += d + 2 * LSB(c) * LSB(d);  b = rotr64(b ^ c, 63)
#define ROUND(v0,  v1,  v2,  v3,  v4,  v5,  v6,  v7,    \
              v8,  v9, v10, v11, v12, v13, v14, v15)    \
    G(v0, v4,  v8, v12);  G(v1, v5,  v9, v13);          \
    G(v2, v6, v10, v14);  G(v3, v7, v11, v15);          \
    G(v0, v5, v10, v15);  G(v1, v6, v11, v12);          \
    G(v2, v7,  v8, v13);  G(v3, v4,  v9, v14)

    // column rounds (work_block = Q)
    for (int i = 0; i < 128; i += 16) {
        ROUND(work_block->a[i     ], work_block->a[i +  1],
              work_block->a[i +  2], work_block->a[i +  3],
              work_block->a[i +  4], work_block->a[i +  5],
              work_block->a[i +  6], work_block->a[i +  7],
              work_block->a[i +  8], work_block->a[i +  9],
              work_block->a[i + 10], work_block->a[i + 11],
              work_block->a[i + 12], work_block->a[i + 13],
              work_block->a[i + 14], work_block->a[i + 15]);
    }
    // row rounds (work_block = Z)
    for (int i = 0; i < 16; i += 2) {
        ROUND(work_block->a[i      ], work_block->a[i +   1],
              work_block->a[i +  16], work_block->a[i +  17],
              work_block->a[i +  32], work_block->a[i +  33],
              work_block->a[i +  48], work_block->a[i +  49],
              work_block->a[i +  64], work_block->a[i +  65],
              work_block->a[i +  80], work_block->a[i +  81],
              work_block->a[i +  96], work_block->a[i +  97],
              work_block->a[i + 112], work_block->a[i + 113]);
    }
}

static void
binary_g(block *result, block *x, block *y, void (*xcopy) (block*, const block*))
{
    // puts R = X ^ Y into tmp
    block tmp;
    copy_block(&tmp  ,    x);
    xor_block (&tmp  ,    y);

    xcopy(result, &tmp);     // save R (erase or xor the old block)
    g_rounds(&tmp);          // tmp = Z
    xor_block(result, &tmp); // result =  R ^ Z (or R ^ Z ^ old)
}

typedef struct gidx_ctx {
    block    b;
    uint32_t pass_number;
    uint32_t slice_number;
    uint32_t nb_blocks;
    uint32_t nb_iterations;
    uint32_t ctr;
    uint32_t next_index;
} gidx_ctx;

static void
gidx_init(gidx_ctx *ctx,
          uint32_t pass_number,
          uint32_t slice_number,
          uint32_t nb_blocks,
          uint32_t nb_iterations)
{
    ctx->pass_number   = pass_number;
    ctx->slice_number  = slice_number;
    ctx->nb_blocks     = nb_blocks;
    ctx->nb_iterations = nb_iterations;
    ctx->ctr           = 0;   // first block starts by 1.
    ctx->next_index    = 128; // will force increment of ctr upon gidx_next().
}

static uint64_t
gidx_next(gidx_ctx *ctx, uint32_t current_block)
{
    // lazily create the index block we need
    if (ctx->next_index == 128) {
        ctx->next_index = 0;
        ctx->ctr++;
        // refreshe the underlying block
        zero_block(&(ctx->b));
        ctx->b.a[0] = ctx->pass_number;
        ctx->b.a[1] = 0;              // lane number (we have only one)
        ctx->b.a[2] = ctx->slice_number;
        ctx->b.a[3] = ctx->nb_blocks;
        ctx->b.a[4] = ctx->nb_iterations;
        ctx->b.a[5] = 1;              // type: Argon2i
        ctx->b.a[6] = ctx->ctr;
        g_rounds(&(ctx->b));
    }
    // we don't need J2, because there's only one lane.
    uint64_t j1 = ctx->b.a[ctx->next_index]; // 32 least significant bits
    ctx->next_index++;

    _Bool    first_pass = ctx->pass_number == 1; // first pass == 1, not zero
    uint32_t lane_size  = ctx->nb_blocks;
    uint32_t area_size  = first_pass ? current_block - 1 : lane_size - 2;
    uint64_t x          = (j1 * j1)           >> 32;
    uint64_t y          = (area_size * x) >> 32;
    uint64_t z          = area_size - 1 - y;
    uint32_t start_pos  = first_pass ? 0 : current_block + 1;
    return (start_pos + z) % lane_size;
}

void
crypto_Argon2i_hash(uint8_t       *tag,       uint32_t tag_size,
                    const uint8_t *password,  uint32_t password_size,
                    const uint8_t *salt,      uint32_t salt_size,
                    const uint8_t *key,       uint32_t key_size,
                    const uint8_t *ad,        uint32_t ad_size,
                    void *work_area,
                    uint32_t nb_blocks,
                    uint32_t nb_iterations)
{
    // work area seen as blocks (must be suitably aligned)
    block *blocks = work_area;

    {
        uint8_t buf[4];
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx);
        store32_le(buf, 1    /* p */ ); crypto_blake2b_update(&ctx, buf, 4);
        store32_le(buf, tag_size     ); crypto_blake2b_update(&ctx, buf, 4);
        store32_le(buf, nb_blocks    ); crypto_blake2b_update(&ctx, buf, 4);
        store32_le(buf, nb_iterations); crypto_blake2b_update(&ctx, buf, 4);
        store32_le(buf, 0x13 /* v */ ); crypto_blake2b_update(&ctx, buf, 4);
        store32_le(buf, 1    /* y */ ); crypto_blake2b_update(&ctx, buf, 4);
        store32_le(buf, password_size); crypto_blake2b_update(&ctx, buf, 4);
        crypto_blake2b_update(&ctx, password, password_size);
        store32_le(buf, salt_size    ); crypto_blake2b_update(&ctx, buf, 4);
        crypto_blake2b_update(&ctx, salt, salt_size);
        store32_le(buf, key_size     ); crypto_blake2b_update(&ctx, buf, 4);
        crypto_blake2b_update(&ctx, key, key_size);
        store32_le(buf, ad_size      ); crypto_blake2b_update(&ctx, buf, 4);
        crypto_blake2b_update(&ctx, ad, ad_size);

        uint8_t initial_hash[72]; // 64 bytes plus additional words for future hashes
        crypto_blake2b_final(&ctx, initial_hash);

        // fill first 2 blocks
        block   tmp_block;
        uint8_t hash_area[1024];
        store32_le(initial_hash + 64, 0); // first  additional word
        store32_le(initial_hash + 68, 0); // second additional word
        extended_hash(hash_area, 1024, initial_hash, 72);
        load_block(&tmp_block, hash_area);
        copy_block(blocks, &tmp_block);

        store32_le(initial_hash + 68, 1); // slight modification
        extended_hash(hash_area, 1024, initial_hash, 72);
        load_block(&tmp_block, hash_area);
        xor_block(blocks + 1, &tmp_block);
    }

    // Actual number of blocks
    nb_blocks -= nb_blocks % 4; // round down to 4 p (p == 1 thread)
    const uint32_t segment_size = nb_blocks / 4;

    // fill the rest of the first segment
    {
        gidx_ctx ctx;
        gidx_init(&ctx, 1, 1, nb_blocks, nb_iterations);
        for (uint32_t i = 2; i < segment_size; i++) {
            binary_g(blocks + i,                  // current block
                     blocks + i - 1,              // previous block
                     blocks + gidx_next(&ctx, i), // reference block
                     copy_block);                 // first pass is a raw copy
        }
    }
    // fill the other 3 segments
    for (int segment = 1; segment < 4; segment++ ) {
        gidx_ctx ctx;
        gidx_init(&ctx, 1, segment + 1, nb_blocks, nb_iterations);
        for (uint32_t i = segment * segment_size;
             i < (segment + 1) * segment_size;
             i++) {
            binary_g(blocks + i,                  // current block
                     blocks + i - 1,              // previous block
                     blocks + gidx_next(&ctx, i), // reference block
                     copy_block);                 // first pass is a raw copy
        }
    }

    // subsequent iterations (xor computations with previous results)
    for (int segment = 0; segment < 4; segment++ ) {
        gidx_ctx ctx;
        gidx_init(&ctx, 1, segment + 1, nb_blocks, nb_iterations);
        for (uint32_t i = segment * segment_size;
             i < (segment + 1) * segment_size;
             i++) {
            binary_g(blocks + i,                   // current block
                     blocks + (i - 1) % nb_blocks, // previous block (modulo!)
                     blocks + gidx_next(&ctx, i),  // reference block
                     xor_block);                   // subsequent passes are XOR
        }
    }

    // hash the very last block with H' into the output tag
    uint8_t final_block[1024];
    store_block(final_block, blocks + (nb_blocks - 1));
    extended_hash(tag, tag_size, final_block, 1024);
}
