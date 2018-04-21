#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "monocypher.h"
#include "sha512.h"
#include "utils.h"
#include "vectors.h"

#define CHACHA_BLOCK_SIZE    64
#define CHACHA_NB_BLOCKS     10
#define POLY1305_BLOCK_SIZE  16
#define BLAKE2B_BLOCK_SIZE  128
#define SHA_512_BLOCK_SIZE  128
#define COMPARISON_DIFF_THRESHOLD 0.04

/////////////////
/// Utilities ///
/////////////////

static void* alloc(size_t size)
{
    void *buf = malloc(size);
    if (buf == NULL) {
        fprintf(stderr, "Allocation failed: 0x%zx bytes\n", size);
        exit(1);
    }
    return buf;
}

typedef struct {
    u8     *buf;
    size_t  size;
} vector;

int zerocmp(const u8 *p, size_t n)
{
    FOR (i, 0, n) {
        if (p[i] != 0) { return -1; }
    }
    return 0;
}

static int test(void (*f)(const vector[], vector*),
                const char *name, size_t nb_inputs,
                size_t nb_vectors, u8 **vectors, size_t *sizes)
{
    int     status   = 0;
    int     nb_tests = 0;
    size_t  idx      = 0;
    vector *in;
    in = (vector*)alloc(nb_vectors * sizeof(vector));
    while (idx < nb_vectors) {
        size_t out_size = sizes[idx + nb_inputs];
        vector out;
        out.buf  = (u8*)alloc(out_size);
        out.size = out_size;
        FOR (i, 0, nb_inputs) {
            in[i].buf  = vectors[idx+i];
            in[i].size = sizes  [idx+i];
        }
        f(in, &out);
        vector expected;
        expected.buf  = vectors[idx+nb_inputs];
        expected.size = sizes  [idx+nb_inputs];
        status |= out.size - expected.size;
        if (out.size != 0) {
            status |= memcmp(out.buf, expected.buf, out.size);
        }
        free(out.buf);
        idx += nb_inputs + 1;
        nb_tests++;
    }
    free(in);
    printf("%s %4d tests: %s\n",
           status != 0 ? "FAILED" : "OK", nb_tests, name);
    return status;
}

#define TEST(name, nb_inputs) test(name, #name, nb_inputs, \
                                   nb_##name##_vectors,    \
                                   name##_vectors,         \
                                   name##_sizes)

////////////////////////
/// The tests proper ///
////////////////////////
static void chacha20(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *nonce = in + 1;
    const vector *plain = in + 2;
    u64 ctr = load64_le(in[3].buf);
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key->buf, nonce->buf);
    crypto_chacha20_set_ctr(&ctx, ctr);
    crypto_chacha20_encrypt(&ctx, out->buf, plain->buf, plain->size);
}

static void xchacha20(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *nonce = in + 1;
    const vector *plain = in + 2;
    u64 ctr = load64_le(in[3].buf);
    crypto_chacha_ctx ctx;
    crypto_chacha20_x_init (&ctx, key->buf, nonce->buf);
    crypto_chacha20_set_ctr(&ctx, ctr);
    crypto_chacha20_encrypt(&ctx, out->buf, plain->buf, plain->size);
}

static void poly1305(const vector in[], vector *out)
{
    const vector *key = in;
    const vector *msg = in + 1;
    crypto_poly1305(out->buf, msg->buf, msg->size, key->buf);
}

static void aead_ietf(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *nonce = in + 1;
    const vector *ad    = in + 2;
    const vector *text  = in + 3;
    crypto_lock_aead(out ->buf, out->buf + 16, key->buf, nonce->buf,
                     ad->buf, ad->size, text->buf, text->size);
}


static void blake2b(const vector in[], vector *out)
{
    const vector *msg = in;
    const vector *key = in + 1;
    crypto_blake2b_general(out->buf, out->size,
                           key->buf, key->size,
                           msg->buf, msg->size);
}

static void sha512(const vector in[], vector *out)
{
    crypto_sha512(out->buf, in->buf, in->size);
}

static void argon2i(const vector in[], vector *out)
{
    u64 nb_blocks     = load64_le(in[0].buf);
    u64 nb_iterations = load64_le(in[1].buf);
    const vector *password = in + 2;
    const vector *salt     = in + 3;
    const vector *key      = in + 4;
    const vector *ad       = in + 5;

    void *work_area = alloc(nb_blocks * 1024);
    crypto_argon2i_general(out->buf, out->size,
                           work_area, nb_blocks, nb_iterations,
                           password->buf, password->size,
                           salt    ->buf, salt    ->size,
                           key     ->buf, key     ->size,
                           ad      ->buf, ad      ->size);
    free(work_area);
}

static void x25519(const vector in[], vector *out)
{
    const vector *scalar = in;
    const vector *point  = in + 1;
    int report   = crypto_x25519(out->buf, scalar->buf, point->buf);
    int not_zero = zerocmp(out->buf, out->size);
    if ( not_zero &&  report)  printf("FAILURE: x25519 false all_zero report\n");
    if (!not_zero && !report)  printf("FAILURE: x25519 failed to report zero\n");
}

static void key_exchange(const vector in[], vector *out)
{
    const vector *secret_key = in;
    const vector *public_key = in + 1;
    crypto_key_exchange(out->buf, secret_key->buf, public_key->buf);
}

static void edDSA(const vector in[], vector *out)
{
    const vector *secret_k = in;
    const vector *public_k = in + 1;
    const vector *msg      = in + 2;
    u8            out2[64];

    // Sign with cached public key, then by reconstructing the key
    crypto_sign(out->buf, secret_k->buf, public_k->buf, msg->buf, msg->size);
    crypto_sign(out2    , secret_k->buf, 0            , msg->buf, msg->size);
    // Compare signatures (must be the same)
    if (memcmp(out->buf, out2, out->size)) {
        printf("FAILURE: reconstructing public key"
               " yields different signature\n");
    }
}

#ifdef ED25519_SHA512
static void (*ed_25519)(const vector[], vector*) = edDSA;
#endif

static void iterate_x25519(u8 k[32], u8 u[32])
{
    u8 tmp[32];
    crypto_x25519(tmp , k, u);
    memcpy(u, k  , 32);
    memcpy(k, tmp, 32);
}

static int test_x25519()
{
    u8 _1   [32] = {0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
                    0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
                    0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
                    0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79};
    u8 k[32] = {9};
    u8 u[32] = {9};

    crypto_x25519_public_key(k, u);
    int status = memcmp(k, _1, 32);
    printf("%s: x25519 1\n", status != 0 ? "FAILED" : "OK");

    u8 _1k  [32] = {0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
                    0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
                    0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
                    0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51};
    FOR (i, 1, 1000) { iterate_x25519(k, u); }
    status |= memcmp(k, _1k, 32);
    printf("%s: x25519 1K\n", status != 0 ? "FAILED" : "OK");

    // too long; didn't run
    //u8 _1M[32] = {0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd,
    //              0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f,
    //              0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf,
    //              0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24};
    //FOR (i, 1000, 1000000) { iterate_x25519(k, u); }
    //status |= memcmp(k, _1M, 32);
    //printf("%s: x25519 1M\n", status != 0 ? "FAILED" : "OK");
    return status;
}

//////////////////////////////
/// Self consistency tests ///
//////////////////////////////

static int p_verify(size_t size, int (*compare)(const u8*, const u8*))
{
    int status = 0;
    u8 a[64]; // size <= 64
    u8 b[64]; // size <= 64
    FOR (i, 0, 256) {
        FOR (j, 0, 256) {
            // Set every byte to the chosen value, then compare
            FOR (k, 0, size) {
                a[k] = i;
                b[k] = j;
            }
            int cmp = compare(a, b);
            status |= (i == j ? cmp : ~cmp);
            // Set only two bytes to the chosen value, then compare
            FOR (k, 0, size / 2) {
                FOR (l, 0, size) {
                    a[l] = 0;
                    b[l] = 0;
                }
                a[k] = i; a[k + size/2] = i;
                b[k] = j; b[k + size/2] = j;
                int cmp = compare(a, b);
                status |= (i == j ? cmp : ~cmp);
            }
        }
    }
    printf("%s: crypto_verify%zu\n", status != 0 ? "FAILED" : "OK", size);
    return status;
}
static int p_verify16(){ return p_verify(16, crypto_verify16); }
static int p_verify32(){ return p_verify(32, crypto_verify32); }
static int p_verify64(){ return p_verify(64, crypto_verify64); }


// Tests that encrypting in chunks yields the same result than
// encrypting all at once.
static int p_chacha20()
{
#undef INPUT_SIZE
#define INPUT_SIZE (CHACHA_BLOCK_SIZE * 4) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 output_chunk[INPUT_SIZE];
        u8 output_whole[INPUT_SIZE];
        // inputs
        u8 input       [INPUT_SIZE];  p_random(input, INPUT_SIZE);
        u8 key         [32];          p_random(key  , 32);
        u8 nonce       [8];           p_random(nonce, 8);

        // Encrypt in chunks
        crypto_chacha_ctx ctx;
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_encrypt(&ctx, output_chunk  , input  , i);
        crypto_chacha20_encrypt(&ctx, output_chunk+i, input+i, INPUT_SIZE-i);
        // Encrypt all at once
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_encrypt(&ctx, output_whole, input, INPUT_SIZE);
        // Compare
        status |= memcmp(output_chunk, output_whole, INPUT_SIZE);

        // Stream in chunks
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_stream(&ctx, output_chunk    , i);
        crypto_chacha20_stream(&ctx, output_chunk + i, INPUT_SIZE - i);
        // Stream all at once
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_stream(&ctx, output_whole, INPUT_SIZE);
        // Compare
        status |= memcmp(output_chunk, output_whole, INPUT_SIZE);
    }
    printf("%s: Chacha20 (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that output and input can be the same pointer
static int p_chacha20_same_ptr()
{
    int status = 0;
    u8 input       [INPUT_SIZE];  p_random(input, INPUT_SIZE);
    u8 key         [32];          p_random(key  , 32);
    u8 nonce       [8];           p_random(nonce, 8);
    u8 output      [INPUT_SIZE];
    crypto_chacha_ctx ctx;
    crypto_chacha20_init   (&ctx, key, nonce);
    crypto_chacha20_encrypt(&ctx, output, input, INPUT_SIZE);
    crypto_chacha20_init   (&ctx, key, nonce);
    crypto_chacha20_encrypt(&ctx, input, input, INPUT_SIZE);
    status |= memcmp(output, input, CHACHA_BLOCK_SIZE);
    printf("%s: Chacha20 (output == input)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_chacha20_set_ctr()
{
#define STREAM_SIZE (CHACHA_BLOCK_SIZE * CHACHA_NB_BLOCKS)
    int status = 0;
    FOR (i, 0, 1000) {
        u8 output_part[STREAM_SIZE    ];
        u8 output_all [STREAM_SIZE    ];
        u8 output_more[STREAM_SIZE * 2];
        u8 key        [32];          p_random(key  , 32);
        u8 nonce      [8];           p_random(nonce, 8 );
        u64 ctr      = rand64() % CHACHA_NB_BLOCKS;
        size_t limit = ctr * CHACHA_BLOCK_SIZE;
        // Encrypt all at once
        crypto_chacha_ctx ctx;
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_stream(&ctx, output_all, STREAM_SIZE);
        // Encrypt second part
        crypto_chacha20_set_ctr(&ctx, ctr);
        crypto_chacha20_stream(&ctx, output_part + limit, STREAM_SIZE - limit);
        // Encrypt first part
        crypto_chacha20_set_ctr(&ctx, 0);
        crypto_chacha20_stream(&ctx, output_part, limit);
        // Compare the results (must be the same)
        status |= memcmp(output_part, output_all, STREAM_SIZE);

        // Encrypt before the begining
        crypto_chacha20_set_ctr(&ctx, -ctr);
        crypto_chacha20_stream(&ctx,
                               output_more + STREAM_SIZE - limit,
                               STREAM_SIZE + limit);
        // Compare the results (must be the same)
        status |= memcmp(output_more + STREAM_SIZE, output_all, STREAM_SIZE);
    }
    printf("%s: Chacha20 (set counter)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that authenticating bit by bit yields the same mac than
// authenticating all at once
static int p_poly1305()
{
#undef INPUT_SIZE
#define INPUT_SIZE (POLY1305_BLOCK_SIZE * 4) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 mac_chunk[16];
        u8 mac_whole[16];
        // inputs
        u8 input[INPUT_SIZE];  p_random(input, INPUT_SIZE);
        u8 key  [32];          p_random(key  , 32);

        // Authenticate bit by bit
        crypto_poly1305_ctx ctx;
        crypto_poly1305_init(&ctx, key);
        crypto_poly1305_update(&ctx, input    , i);
        crypto_poly1305_update(&ctx, input + i, INPUT_SIZE - i);
        crypto_poly1305_final(&ctx, mac_chunk);

        // Authenticate all at once
        crypto_poly1305(mac_whole, input, INPUT_SIZE, key);

        // Compare the results (must be the same)
        status |= memcmp(mac_chunk, mac_whole, 16);
    }
    printf("%s: Poly1305 (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of poly1305 can overlap.
static int p_poly1305_overlap()
{
#undef INPUT_SIZE
#define INPUT_SIZE (POLY1305_BLOCK_SIZE + (2 * 16)) // total input size
    int status = 0;
    FOR (i, 0, POLY1305_BLOCK_SIZE + 16) {
        u8 input[INPUT_SIZE];  p_random(input, INPUT_SIZE);
        u8 key  [32];          p_random(key  , 32);
        u8 mac  [16];
        crypto_poly1305(mac    , input + 16, POLY1305_BLOCK_SIZE, key);
        crypto_poly1305(input+i, input + 16, POLY1305_BLOCK_SIZE, key);
        status |= memcmp(mac, input + i, 16);
    }
    printf("%s: Poly1305 (overlaping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that hashing bit by bit yields the same hash than hashing all
// at once.  Note: I figured we didn't need to test keyed mode, or
// different hash sizes, again.  This test sticks to the simplified
// interface.
static int p_blake2b()
{
#undef INPUT_SIZE
#define INPUT_SIZE (BLAKE2B_BLOCK_SIZE * 4) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 hash_chunk[64];
        u8 hash_whole[64];
        // inputs
        u8 input[INPUT_SIZE];  p_random(input, INPUT_SIZE);

        // Authenticate bit by bit
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx);
        crypto_blake2b_update(&ctx, input    , i);
        crypto_blake2b_update(&ctx, input + i, INPUT_SIZE - i);
        crypto_blake2b_final(&ctx, hash_chunk);

        // Authenticate all at once
        crypto_blake2b(hash_whole, input, INPUT_SIZE);

        // Compare the results (must be the same)
        status |= memcmp(hash_chunk, hash_whole, 64);
    }
    printf("%s: Blake2b (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of Blake2b can overlap.
static int p_blake2b_overlap()
{
#undef INPUT_SIZE
#define INPUT_SIZE (BLAKE2B_BLOCK_SIZE + (2 * 64)) // total input size
    int status = 0;
    FOR (i, 0, BLAKE2B_BLOCK_SIZE + 64) {
        u8 input[INPUT_SIZE];  p_random(input, INPUT_SIZE);
        u8 hash [64];
        crypto_blake2b(hash   , input + 64, BLAKE2B_BLOCK_SIZE);
        crypto_blake2b(input+i, input + 64, BLAKE2B_BLOCK_SIZE);
        status |= memcmp(hash, input + i, 64);
    }
    printf("%s: Blake2b (overlaping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that hashing bit by bit yields the same hash than hashing all
// at once. (for sha512)
static int p_sha512()
{
#undef INPUT_SIZE
#define INPUT_SIZE (SHA_512_BLOCK_SIZE * 4) // total input size
    int status = 0;
    FOR (i, 0, INPUT_SIZE) {
        // outputs
        u8 hash_chunk[64];
        u8 hash_whole[64];
        // inputs
        u8 input[INPUT_SIZE];  p_random(input, INPUT_SIZE);

        // Authenticate bit by bit
        crypto_sha512_ctx ctx;
        crypto_sha512_init(&ctx);
        crypto_sha512_update(&ctx, input    , i);
        crypto_sha512_update(&ctx, input + i, INPUT_SIZE - i);
        crypto_sha512_final(&ctx, hash_chunk);

        // Authenticate all at once
        crypto_sha512(hash_whole, input, INPUT_SIZE);

        // Compare the results (must be the same)
        status |= memcmp(hash_chunk, hash_whole, 64);
    }
    printf("%s: Sha512 (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of crypto_sha_512 can overlap.
static int p_sha512_overlap()
{
#undef INPUT_SIZE
#define INPUT_SIZE (SHA_512_BLOCK_SIZE + (2 * 64)) // total input size
    int status = 0;
    FOR (i, 0, SHA_512_BLOCK_SIZE + 64) {
        u8 input[INPUT_SIZE];  p_random(input, INPUT_SIZE);
        u8 hash [64];
        crypto_sha512(hash   , input + 64, SHA_512_BLOCK_SIZE);
        crypto_sha512(input+i, input + 64, SHA_512_BLOCK_SIZE);
        status |= memcmp(hash, input + i, 64);
    }
    printf("%s: Sha512 (overlaping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_argon2i_easy()
{
    int   status    = 0;
    void *work_area = alloc(8 * 1024);
    FOR (i, 0, 128) {
        RANDOM_INPUT(password , 32);
        RANDOM_INPUT(salt     , 16);
        u8 hash_general[32];
        u8 hash_easy   [32];
        crypto_argon2i_general(hash_general, 32, work_area, 8, 1,
                               password, 32, salt, 16, 0, 0, 0, 0);
        crypto_argon2i(hash_easy, 32, work_area, 8, 1, password, 32, salt, 16);
        status |= memcmp(hash_general, hash_easy, 32);
   }
    free(work_area);
    printf("%s: Argon2i (easy interface)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_argon2i_overlap()
{
    int status          = 0;
    u8 *work_area       = (u8*)alloc(8 * 1024);
    u8 *clean_work_area = (u8*)alloc(8 * 1024);
    FOR (i, 0, 128) {
        p_random(work_area, 8 * 1024);
        u32 pass_offset = rand64() % 128;
        u32 salt_offset = rand64() % 128;
        u32 key_offset  = rand64() % 128;
        u32 ad_offset   = rand64() % 128;
        u8 hash1[32];
        u8 hash2[32];
        u8 pass [16];  FOR (i, 0, 16) { pass[i] = work_area[i + pass_offset]; }
        u8 salt [16];  FOR (i, 0, 16) { salt[i] = work_area[i + salt_offset]; }
        u8 key  [32];  FOR (i, 0, 32) { key [i] = work_area[i +  key_offset]; }
        u8 ad   [32];  FOR (i, 0, 32) { ad  [i] = work_area[i +   ad_offset]; }

        crypto_argon2i_general(hash1, 32, clean_work_area, 8, 1,
                               pass, 16, salt, 16, key, 32, ad, 32);
        crypto_argon2i_general(hash2, 32, work_area, 8, 1,
                               work_area + pass_offset, 16,
                               work_area + salt_offset, 16,
                               work_area +  key_offset, 32,
                               work_area +   ad_offset, 32);
        status |= memcmp(hash1, hash2, 32);
    }
    free(work_area);
    free(clean_work_area);
    printf("%s: Argon2i (overlaping i/o)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_eddsa_roundtrip()
{
#define MESSAGE_SIZE 32
    int status = 0;
    FOR (i, 0, 1000) {
        RANDOM_INPUT(message, MESSAGE_SIZE);
        RANDOM_INPUT(sk, 32);
        u8 pk       [32];  crypto_sign_public_key(pk, sk);
        u8 signature[64];  crypto_sign(signature, sk, pk, message, MESSAGE_SIZE);
        status |= crypto_check(signature, pk, message, MESSAGE_SIZE);
    }
    printf("%s: EdDSA (roundtrip)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Verifies that random signatures are all invalid.  Uses random
// public keys to see what happens outside of the curve (it should
// yield an invalid signature).
static int p_eddsa_random()
{
    int status = 0;
    u8 message[MESSAGE_SIZE];  p_random(message, 32);
    FOR (i, 0, 1000) {
        RANDOM_INPUT(pk, 32);
        RANDOM_INPUT(signature , 64);
        status |= ~crypto_check(signature, pk, message, MESSAGE_SIZE);
    }
    printf("%s: EdDSA (random)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Tests that the input and output buffers of crypto_check() can overlap.
static int p_eddsa_overlap()
{
    int status = 0;
    FOR(i, 0, MESSAGE_SIZE + 64) {
#undef INPUT_SIZE
#define INPUT_SIZE (MESSAGE_SIZE + (2 * 64)) // total input size
        RANDOM_INPUT(input, INPUT_SIZE);
        RANDOM_INPUT(sk   , 32        );
        u8 pk       [32];  crypto_sign_public_key(pk, sk);
        u8 signature[64];
        crypto_sign(signature, sk, pk, input + 64, MESSAGE_SIZE);
        crypto_sign(input+i  , sk, pk, input + 64, MESSAGE_SIZE);
        status |= memcmp(signature, input + i, 64);
    }
    printf("%s: EdDSA (overlap)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_eddsa_incremental()
{
    int status = 0;
    u8 message[MESSAGE_SIZE];  p_random(message, 32);
    FOR (i, 0, MESSAGE_SIZE) {
        RANDOM_INPUT(message, MESSAGE_SIZE);
        RANDOM_INPUT(sk, 32);
        u8 pk      [32];  crypto_sign_public_key(pk, sk);
        u8 sig_mono[64];  crypto_sign(sig_mono, sk, pk, message, MESSAGE_SIZE);
        u8 sig_incr[64];
        {
            crypto_sign_ctx ctx;
            crypto_sign_init_first_pass (&ctx, sk, pk);
            crypto_sign_update          (&ctx, message    , i);
            crypto_sign_update          (&ctx, message + i, MESSAGE_SIZE - i);
            crypto_sign_init_second_pass(&ctx);
            crypto_sign_update          (&ctx, message    , i);
            crypto_sign_update          (&ctx, message + i, MESSAGE_SIZE - i);
            crypto_sign_final           (&ctx, sig_incr);
        }
        status |= memcmp(sig_mono, sig_incr, 64);
        status |= crypto_check(sig_mono, pk, message, MESSAGE_SIZE);
        {
            crypto_check_ctx ctx;
            crypto_check_init  (&ctx, sig_incr, pk);
            crypto_check_update(&ctx, message    , i);
            crypto_check_update(&ctx, message + i, MESSAGE_SIZE - i);
            status |= crypto_check_final(&ctx);
        }
    }
    printf("%s: EdDSA (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_aead()
{
    int status = 0;
    FOR (i, 0, 1000) {
        u8 key      [32];  p_random(key      , 32);
        u8 nonce    [24];  p_random(nonce    , 24);
        u8 ad       [ 4];  p_random(ad       ,  4);
        u8 plaintext[ 8];  p_random(plaintext,  8);
        u8 box[24], box2[24];
        u8 out[8];
        // AEAD roundtrip
        crypto_lock_aead(box, box+16, key, nonce, ad, 4, plaintext, 8);
        status |= crypto_unlock_aead(out, key, nonce, box, ad, 4, box+16, 8);
        status |= memcmp(plaintext, out, 8);
        box[0]++;
        status |= !crypto_unlock_aead(out, key, nonce, box, ad, 4, box+16, 8);

        // Authenticated roundtrip (easy interface)
        // Make and accept message
        crypto_lock(box, box + 16, key, nonce, plaintext, 8);
        status |= crypto_unlock(out, key, nonce, box, box + 16, 8);
        // Make sure decrypted text and original text are the same
        status |= memcmp(plaintext, out, 8);
        // Make and reject forgery
        box[0]++;
        status |= !crypto_unlock(out, key, nonce, box, box + 16, 8);
        box[0]--; // undo forgery

        // Same result for both interfaces
        crypto_lock_aead(box2, box2 + 16, key, nonce, 0, 0, plaintext, 8);
        status |= memcmp(box, box2, 24);
    }
    printf("%s: aead (roundtrip)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int p_lock_incremental()
{
    int status = 0;
    FOR (i, 0, 1000) {
        RANDOM_INPUT(key  ,  32);
        RANDOM_INPUT(nonce,  24);
        RANDOM_INPUT(ad   , 128);
        RANDOM_INPUT(plain, 256);
        // total sizes
        size_t ad_size    = rand64() % 128;
        size_t text_size  = rand64() % 256;
        // incremental sizes
        size_t ad_size1   = ad_size   == 0 ? 0 : rand64() % ad_size;
        size_t text_size1 = text_size == 0 ? 0 : rand64() % text_size;
        size_t ad_size2   = ad_size   - ad_size1;
        size_t text_size2 = text_size - text_size1;
        // incremental buffers
        u8 *ad1    = ad;    u8 *ad2    = ad + ad_size1;
        u8 *plain1 = plain; u8 *plain2 = plain + text_size1;

        u8 mac1[16], cipher1[256];
        u8 mac2[16], cipher2[256];
        crypto_lock_aead(mac1, cipher1, key, nonce,
                         ad, ad_size, plain, text_size);
        crypto_lock_ctx ctx;
        crypto_lock_init   (&ctx, key, nonce);
        crypto_lock_auth_ad(&ctx, ad1, ad_size1); // just to show ad also have
        crypto_lock_auth_ad(&ctx, ad2, ad_size2); // an incremental interface
        crypto_lock_update (&ctx, cipher2             , plain1, text_size1);
        crypto_lock_update (&ctx, cipher2 + text_size1, plain2, text_size2);
        crypto_lock_final  (&ctx, mac2);
        status |= memcmp(mac1   , mac2   , 16       );
        status |= memcmp(cipher1, cipher2, text_size);

        // Now test the round trip.
        u8 re_plain1[256];
        u8 re_plain2[256];
        status |= crypto_unlock_aead(re_plain1, key, nonce, mac1,
                                     ad, ad_size, cipher1, text_size);
        crypto_unlock_init   (&ctx, key, nonce);
        crypto_unlock_auth_ad(&ctx, ad, ad_size);
        crypto_unlock_update (&ctx, re_plain2, cipher2, text_size);
        status |= crypto_unlock_final(&ctx, mac2);
        status |= memcmp(mac1 , mac2     , 16       );
        status |= memcmp(plain, re_plain1, text_size);
        status |= memcmp(plain, re_plain2, text_size);

        // Test authentication without decryption
        crypto_unlock_init        (&ctx, key, nonce);
        crypto_unlock_auth_ad     (&ctx, ad     , ad_size  );
        crypto_unlock_auth_message(&ctx, cipher2, text_size);
        status |= crypto_unlock_final(&ctx, mac2);
        // The same, except we're supposed to reject forgeries
        if (text_size > 0) {
            cipher2[0]++; // forgery attempt
            crypto_unlock_init        (&ctx, key, nonce);
            crypto_unlock_auth_ad     (&ctx, ad     , ad_size  );
            crypto_unlock_auth_message(&ctx, cipher2, text_size);
            status |= !crypto_unlock_final(&ctx, mac2);
        }
    }
    printf("%s: aead (incremental)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

// Only additionnal data
static int p_auth()
{
    int status = 0;
    FOR (i, 0, 128) {
        u8 key      [ 32];  p_random(key      , 32);
        u8 nonce    [ 24];  p_random(nonce    , 24);
        u8 ad       [128];  p_random(ad       ,  i);
        u8 mac1[16];
        u8 mac2[16];
        // roundtrip
        {
            crypto_lock_ctx ctx;
            crypto_lock_init   (&ctx, key, nonce);
            crypto_lock_auth_ad(&ctx, ad, i);
            crypto_lock_final  (&ctx, mac1);
            crypto_lock_aead(mac2, 0, key, nonce, ad, i, 0, 0);
            status |= memcmp(mac1, mac2, 16);
        }
        {
            crypto_unlock_ctx ctx;
            crypto_unlock_init   (&ctx, key, nonce);
            crypto_unlock_auth_ad(&ctx, ad, i);
            status |= crypto_unlock_final(&ctx, mac1);
            status |= crypto_unlock_aead(0, key, nonce, mac1, ad, i, 0, 0);
        }
    }
    printf("%s: aead (authentication)\n", status != 0 ? "FAILED" : "OK");
    return status;
}

int main(void)
{
    int status = 0;
    printf("\nTest against vectors");
    printf("\n--------------------\n");
    status |= TEST(chacha20    , 4);
    status |= TEST(xchacha20   , 4);
    status |= TEST(poly1305    , 2);
    status |= TEST(aead_ietf   , 4);
    status |= TEST(blake2b     , 2);
    status |= TEST(sha512      , 1);
    status |= TEST(argon2i     , 6);
    status |= TEST(x25519      , 2);
    status |= TEST(key_exchange, 2);
#ifdef ED25519_SHA512
    status |= TEST(ed_25519    , 3);
#else
    status |= TEST(edDSA       , 3);
#endif
    status |= test_x25519();

    printf("\nProperty based tests");
    printf("\n--------------------\n");
    status |= p_verify16();
    status |= p_verify32();
    status |= p_verify64();
    status |= p_chacha20();
    status |= p_chacha20_same_ptr();
    status |= p_chacha20_set_ctr();
    status |= p_poly1305();
    status |= p_poly1305_overlap();
    status |= p_blake2b();
    status |= p_blake2b_overlap();
    status |= p_sha512();
    status |= p_sha512_overlap();
    status |= p_argon2i_easy();
    status |= p_argon2i_overlap();
    status |= p_eddsa_roundtrip();
    status |= p_eddsa_random();
    status |= p_eddsa_overlap();
    status |= p_eddsa_incremental();
    status |= p_aead();
    status |= p_lock_incremental();
    status |= p_auth();

    printf("\n%s\n\n", status != 0 ? "SOME TESTS FAILED" : "All tests OK!");
    return status;
}
