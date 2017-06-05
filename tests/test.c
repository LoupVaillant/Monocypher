#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "sha512.h"

#include "chacha20.h"
#include "argon2i.h"
#include "blake2b.h"
#include "blake2b_easy.h"
#include "ed25519_key.h"
#include "ed25519_sign.h"
#include "h_chacha20.h"
#include "key_exchange.h"
#include "poly1305.h"
#include "v_sha512.h"
#include "x25519.h"
#include "x_chacha20.h"

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
#define sv static void
typedef  int8_t   i8;
typedef uint8_t   u8;
typedef uint32_t u32;
typedef  int32_t i32;
typedef  int64_t i64;
typedef uint64_t u64;

/////////////////
/// Utilities ///
/////////////////

static void* alloc(size_t size)
{
    void *buf = malloc(size);
    if (buf == NULL) {
        fprintf(stderr, "Allocation failed\n");
        exit(1);
    }
    return buf;
}

typedef struct {
    u8     *buf;
    size_t  size;
} vector;

static int test(void (*f)(const vector[], vector*),
                const char *name, size_t nb_inputs,
                size_t nb_vectors, u8 **vectors, size_t *sizes)
{
    int    status   = 0;
    int    nb_tests = 0;
    size_t idx      = 0;
    vector in[nb_vectors];
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
        status |= crypto_memcmp(out.buf, expected.buf, out.size);
        free(out.buf);
        idx += nb_inputs + 1;
        nb_tests++;
    }
    printf("%s %3d tests: %s\n",
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
sv chacha20(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *nonce = in + 1;
    crypto_chacha_ctx ctx;
    crypto_chacha20_init  (&ctx, key->buf, nonce->buf);
    crypto_chacha20_stream(&ctx, out->buf, out->size);
}

sv h_chacha20(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *input = in + 1;
    crypto_chacha20_H(out->buf, key->buf, input->buf);
}

sv x_chacha20(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *nonce = in + 1;
    crypto_chacha_ctx ctx;
    crypto_chacha20_Xinit (&ctx, key->buf, nonce->buf);
    crypto_chacha20_stream(&ctx, out->buf, out->size);
}

sv blake2b(const vector in[], vector *out)
{
    const vector *msg = in;
    const vector *key = in + 1;
    crypto_blake2b_general(out->buf, out->size,
                           key->buf, key->size,
                           msg->buf, msg->size);
}

sv blake2b_easy(const vector in[], vector *out)
{
    crypto_blake2b(out->buf, in->buf, in->size);
}

sv poly1305(const vector in[], vector *out)
{
    const vector *key = in;
    const vector *msg = in + 1;
    crypto_poly1305_auth(out->buf, msg->buf, msg->size, key->buf);
}

sv argon2i(const vector in[], vector *out)
{
    u32 nb_blocks = 0;
    u32 nb_iterations = 0;
    FOR (i, 0, in[0].size) {nb_blocks     <<= 8; nb_blocks     += in[0].buf[i];}
    FOR (i, 0, in[1].size) {nb_iterations <<= 8; nb_iterations += in[1].buf[i];}
    const vector *password      = in + 2;
    const vector *salt          = in + 3;
    const vector *key           = in + 4;
    const vector *ad            = in + 5;
    void         *work_area     = alloc(nb_blocks * 1024);
    crypto_argon2i(out->buf, out->size,
                   work_area, nb_blocks, nb_iterations,
                   password->buf, password->size,
                   salt    ->buf, salt    ->size,
                   key     ->buf, key     ->size,
                   ad      ->buf, ad      ->size);
    free(work_area);
}

sv x25519(const vector in[], vector *out)
{
    const vector *scalar = in;
    const vector *point  = in + 1;
    int report   = crypto_x25519(out->buf, scalar->buf, point->buf);
    int not_zero = crypto_zerocmp(out->buf, out->size);
    if ( not_zero &&  report)  printf("FAILURE: x25519 false all_zero report\n");
    if (!not_zero && !report)  printf("FAILURE: x25519 failed to report zero\n");
}

sv iterate_x25519(u8 k[32], u8 u[32])
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
    int status = crypto_memcmp(k, _1, 32);
    printf("%s: x25519 1\n", status != 0 ? "FAILED" : "OK");

    u8 _1k  [32] = {0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
                    0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
                    0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
                    0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51};
    FOR (i, 1, 1000) { iterate_x25519(k, u); }
    status |= crypto_memcmp(k, _1k, 32);
    printf("%s: x25519 1K\n", status != 0 ? "FAILED" : "OK");

    // too long; didn't run
    //u8 _100k[32] = {0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd,
    //                0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f,
    //                0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf,
    //                0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24};
    //FOR (i, 1000, 1000000) { iterate_x25519(k, u); }
    //status |= crypto_memcmp(k, _100k, 32);
    //printf("%s: x25519 1M\n", status != 0 ? "FAILED" : "OK");
    return status;
}

sv v_sha512(const vector in[], vector *out)
{
    crypto_sha512(out->buf, in->buf, in->size);
}

sv ed25519_key(const vector in[], vector *out)
{
    crypto_sign_public_key(out->buf, in->buf);
}

sv ed25519_sign(const vector in[], vector *out)
{
    const vector *secret_k = in;
    const vector *public_k = in + 1;
    const vector *msg      = in + 2;
    u8            out2[64];

    // Sign with cached public key, then by reconstructing the key
    crypto_sign(out->buf, secret_k->buf, public_k->buf, msg->buf, msg->size);
    crypto_sign(out2    , secret_k->buf, 0            , msg->buf, msg->size);
    // Compare signatures (must be the same)
    if (crypto_memcmp(out->buf, out2, out->size)) {
        printf("FAILURE: reconstructing public key"
               " yields different signature\n");
    }

    // test successful signature verification
    if (crypto_check(out->buf, public_k->buf, msg->buf, msg->size)) {
        printf("FAILURE: signature check failed to recognise signature\n");
    }
    // test forgery rejections
    u8 fake_signature1[64];
    u8 fake_signature2[64];
    FOR (i, 0, 64) {
        fake_signature1[i] = out->buf[i] + 1;
        fake_signature2[i] = out->buf[i] + 1;
    }
    if (!crypto_check(fake_signature1, public_k->buf, msg->buf, msg->size) ||
        !crypto_check(fake_signature2, public_k->buf, msg->buf, msg->size)) {
        printf("FAILURE: signature check failed to reject forgery\n");
    }
}

sv key_exchange(const vector in[], vector *out)
{
    const vector *secret_key = in;
    const vector *public_key = in + 1;
    crypto_key_exchange(out->buf, secret_key->buf, public_key->buf);
}

static int test_aead()
{
    u8 key[32]      = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
                        0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7 };
    u8 nonce[24]    = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                        1, 1, 1, 1, 1, 1, 1, 1 };
    u8 ad       [4] = { 3, 2, 1, 0 };
    u8 plaintext[8] = { 7, 6, 5, 4, 3, 2, 1, 0 };
    u8 box[24], box2[24];
    u8 out[8];
    int status = 0;
    // AEAD roundtrip
    crypto_aead_lock(box, box+16, key, nonce, ad, 4, plaintext, 8);
    status |= crypto_aead_unlock(out, key, nonce, box, ad, 4, box+16, 8);
    status |= crypto_memcmp(plaintext, out, 8);
    box[0]++;
    status |= !crypto_aead_unlock(out, key, nonce, box, ad, 4, box+16, 8);
    printf("%s: aead (detached)\n", status != 0 ? "FAILED" : "OK");

    // Authenticated roundtrip (easy interface)
    crypto_lock(box, box + 16, key, nonce, plaintext, 8);       // make message
    status |= crypto_unlock(out, key, nonce, box, box + 16, 8); // accept message
    status |= crypto_memcmp(plaintext, out, 8);                 // roundtrip
    box[0]++;                                                   // make forgery
    status |= !crypto_unlock(out, key, nonce, box, box + 16, 8);// reject forgery
    printf("%s: aead (simplified)\n", status != 0 ? "FAILED" : "OK");
    box[0]--; // undo forgery

    // Same result for both interfaces
    crypto_aead_lock(box2, box2 + 16, key, nonce, 0, 0, plaintext, 8);
    status |= crypto_memcmp(box, box2, 24);
    printf("%s: aead (compared)\n", status != 0 ? "FAILED" : "OK");

    return status;
}

int main(void)
{
    int status = 0;
    /* status |= generic_test(equal, "tests/vectors/test_equal"  , 2); */
    /* status |= generic_test(diff , "tests/vectors/test_diff"   , 2); */
    status |= TEST(chacha20    , 2);
    status |= TEST(h_chacha20  , 2);
    status |= TEST(x_chacha20  , 2);
    status |= TEST(blake2b     , 2);
    status |= TEST(blake2b_easy, 1);
    status |= TEST(poly1305    , 2);
    status |= TEST(argon2i     , 6);
    status |= TEST(x25519      , 2);
    status |= TEST(key_exchange, 2);
    status |= TEST(v_sha512    , 1);
    status |= TEST(ed25519_key , 1);
    status |= TEST(ed25519_sign, 3);
    status |= test_x25519();
    status |= test_aead();
    return status;
}
