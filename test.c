#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include "chacha20.h"
#include "blake2b.h"
#include "poly1305.h"
#include "argon2i.h"
#include "ae.h"
#include "lock.h"
#include "x25519.h"
#include "ed25519.h"
#include "sha512.h"

/////////////////////////
/// General utilities ///
/////////////////////////
static void* alloc(size_t size)
{
    void *buffer = malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Allocation failed\n");
        exit(1);
    }
    return buffer;
}

static FILE* file_open(char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Could not open file %s", filename);
        exit(1);
    }
    return file;
}

static unsigned uint_of_char(unsigned char c)
{
    if (c >= '0' && c <= '9') { return c - '0';      }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    fprintf(stderr,
            "'%c' (%d): Not a hexadecimal char"
            " (note: they go in pairs)\n", c, c);
    exit(1);
}

////////////////////////
/// Vector of octets ///
////////////////////////
typedef struct {
    uint8_t *buffer;
    size_t   buf_size;
    size_t   size;
} vector;

static vector vec_new(size_t buf_size)
{
    vector v;
    v.buffer   = alloc(buf_size);
    v.buf_size = buf_size;
    v.size = 0;
    return v;
}

static vector vec_uninitialized(size_t size)
{
    vector v = vec_new(size);
    v.size = size;
    return v;
}

static void vec_del(vector *v)
{
    free(v->buffer);
}

static void vec_push_back(vector *v, uint8_t e)
{
    if (v->buf_size == v->size) {
        // double initial buffer size (and then some)
        size_t   new_buf_size = v->buf_size * 2 + 1;
        uint8_t *new_buffer   = alloc(new_buf_size);
        memcpy(new_buffer, v->buffer, v->buf_size);
        free(v->buffer);
        v->buffer   = new_buffer;
        v->buf_size = new_buf_size;
    }
    v->buffer[v->size] = e;
    v->size++;
}

static int vec_cmp(const vector *u, const vector *v)
{
    if (u->size != v-> size)
        return -1;
    return memcmp(u->buffer, v->buffer, u->size);
}

// Read a line into a vector
// Free the vector's memory with vec_del()
static vector read_hex_line(FILE *input_file)
{
    char c = getc(input_file);
    while (c != '\t') {
        c = getc(input_file);
    }
    vector v = vec_new(64);
    c        = getc(input_file);
    while (c != '\n') {
        uint8_t msb = uint_of_char(c);  c = getc(input_file);
        uint8_t lsb = uint_of_char(c);  c = getc(input_file);
        vec_push_back(&v, lsb | (msb << 4));
    }
    return v;
}

/////////////////////////////
/// Test helper functions ///
/////////////////////////////

// Pulls some test vectors, feed it to f, get a status back
// The test fails if the status is not zero
static int generic_test(int (*f)(const vector[]),
                        char * filename, size_t nb_vectors)
{
    int     status   = 0;
    FILE   *file     = file_open(filename);
    vector *inputs   = alloc(nb_vectors * sizeof(vector));
    int     nb_tests = 0;

    while (getc(file) != EOF) {
        for (size_t i = 0; i < nb_vectors; i++)
            inputs[i] = read_hex_line(file);

        status |= f(inputs);

        for (size_t i = 0; i < nb_vectors; i++)
            vec_del(inputs + i);
        nb_tests++;
    }
    printf("%s %3d tests: %s\n",
           status != 0 ? "FAILED" : "OK", nb_tests, filename);
    free(inputs);
    fclose(file);
    return status;
}

// Same, except f writes to a buffer.  If it's different than
// some expected result, the test fails.
static int test(void (*f)(const vector[], vector*),
                char *filename, size_t nb_vectors)
{
    int     status   = 0;
    FILE   *file     = file_open(filename);
    vector *inputs   = alloc(nb_vectors * sizeof(vector));
    int     nb_tests = 0;

    while (getc(file) != EOF) {
        for (size_t i = 0; i < nb_vectors; i++)
            inputs[i] = read_hex_line(file);

        vector expected = read_hex_line(file);
        vector output   = vec_uninitialized(expected.size);
        f(inputs, &output);
        status |= vec_cmp(&output, &expected);

        vec_del(&output);
        vec_del(&expected);
        for (size_t i = 0; i < nb_vectors; i++)
            vec_del(inputs + i);
        nb_tests++;
    }
    printf("%s %3d tests: %s\n",
           status != 0 ? "FAILED" : "OK", nb_tests, filename);
    free(inputs);
    fclose(file);
    return status;
}

///////////////////////////
/// Test the test suite ///
///////////////////////////
static int equal(const vector v[]) { return  vec_cmp(v, v + 1); }
static int diff (const vector v[]) { return !vec_cmp(v, v + 1); }

////////////////////////
/// The tests proper ///
////////////////////////
static void chacha20(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *nonce = in + 1;
    crypto_chacha_ctx ctx;
    crypto_chacha20_init(&ctx, key->buffer, nonce->buffer);
    crypto_chacha20_random(&ctx, out->buffer, out->size);
}

static void blake2b(const vector in[], vector *out)
{
    const vector *msg = in;
    const vector *key = in + 1;
    crypto_blake2b_general(out->buffer, out->size,
                           key->buffer, key->size,
                           msg->buffer, msg->size);
}

static void poly1305(const vector in[], vector *out)
{
    const vector *key = in;
    const vector *msg = in + 1;
    crypto_poly1305_auth(out->buffer, msg->buffer, msg->size, key->buffer);
}

static void argon2i(const vector in[], vector *out)
{
        const vector *nb_blocks     = in;
        const vector *nb_iterations = in + 1;
        const vector *password      = in + 2;
        const vector *salt          = in + 3;
        const vector *key           = in + 4;
        const vector *ad            = in + 5;
        void         *work_area     = alloc(nb_blocks->buffer[0] * 1024);
        crypto_argon2i_hash(out     ->buffer, out     ->size,
                            password->buffer, password->size,
                            salt    ->buffer, salt    ->size,
                            key     ->buffer, key     ->size,
                            ad      ->buffer, ad      ->size,
                            work_area,
                            nb_blocks    ->buffer[0],
                            nb_iterations->buffer[0]);
        free(work_area);
}

static void x25519(const vector in[], vector *out)
{
    const vector *scalar = in;
    const vector *point  = in + 1;
    crypto_x25519(out->buffer, scalar->buffer, point->buffer);
}

// Disabling the following test, because it takes too damn long
// I suggest you run it once, though.
static void iterate_x25519(uint8_t k[32], uint8_t u[32])
{
    uint8_t tmp[32];
    crypto_x25519(tmp , k, u);
    memcpy(u, k  , 32);
    memcpy(k, tmp, 32);
}

static int test_x25519()
{
    uint8_t _1   [32] = {0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
                         0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
                         0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
                         0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79};
    uint8_t k[32] = {9};
    uint8_t u[32] = {9};

    iterate_x25519(k, u);
    int status = memcmp(k, _1, 32);
    printf("%s: x25519 1\n", status != 0 ? "FAILED" : "OK");

    uint8_t _1k  [32] = {0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
                         0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
                         0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
                         0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51};
    for (int i = 1; i < 1000; i++)
        iterate_x25519(k, u);
    status |= memcmp(k, _1k, 32);
    printf("%s: x25519 1K\n", status != 0 ? "FAILED" : "OK");

    // too long; didn't run
    //uint8_t _100k[32] = {0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd,
    //                     0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f,
    //                     0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf,
    //                     0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24};
    //for (int i = 1000; i < 1000000; i++)
    //    iterate_x25519(k, u);
    //status |= memcmp(k, _100k, 32);
    //printf("%s: x25519 1M\n", status != 0 ? "FAILED" : "OK");
    return status;
}


static void sha512(const vector in[], vector *out)
{
    crypto_sha512(out->buffer, in->buffer, in->size);
}

static void ed25519(const vector in[], vector *out)
{
    const vector *secret  = in;
    const vector *public  = in + 1;
    const vector *message = in + 2;

    // test that secret and public keys match
    uint8_t generated_public[32];
    crypto_ed25519_public_key(generated_public, secret->buffer);
    if (memcmp(generated_public, public->buffer, 32)) {
        printf("FAILURE: secret/public key mismatch!\n");
    }

    // test that signature matches the test vector
    crypto_ed25519_sign(out->buffer,
                        secret->buffer,
                        message->buffer, message->size);

    // test successful signature verification
    if (crypto_ed25519_check(out->buffer, public->buffer,
                             message->buffer, message->size)) {
        printf("FAILURE: signature check failed to recognise signature\n");
    }
    // test forgery rejections
    uint8_t fake_signature1[64];
    uint8_t fake_signature2[64];
    for (int i = 0; i < 64; i++) {
        fake_signature1[i] = out->buffer[i];
        fake_signature2[i] = out->buffer[i];
    }
    fake_signature1[ 0]++; // modify R
    fake_signature2[63]++; // modify s
    if (!crypto_ed25519_check(fake_signature1, public->buffer,
                              message->buffer, message->size) ||
        !crypto_ed25519_check(fake_signature2, public->buffer,
                              message->buffer, message->size)) {
        printf("FAILURE: signature check failed to reject forgery\n");
    }
}

static int test_ae()
{
    uint8_t key[32]      = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
                             0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t nonce[24]    = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
                             0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t plaintext[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t box[24];
    uint8_t out[8];
    int status = 0;
    crypto_ae_lock(box, key, nonce, plaintext, 8);        // make true message
    status |= crypto_ae_unlock(out, key, nonce, box, 8);  // accept true message
    status |= memcmp(plaintext, out, 8);                  // roundtrip
    box[0]++;                                             // make forgery
    status |= !crypto_ae_unlock(out, key, nonce, box, 8); // reject forgery
    printf("%s: authenticated encryption\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int test_lock()
{
    uint8_t rk[32]      = { 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0,
                            1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0 };
    uint8_t sk[32]      = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
                            0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t pk[32]; crypto_x25519_base(pk, sk);
    uint8_t plaintext[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t box[56];
    uint8_t out[8];
    int status = 0;
    crypto_anonymous_lock(box, rk, pk, plaintext, 8);    // make true message
    status |= crypto_anonymous_unlock(out, sk, box, 8);  // accept true message
    status |= memcmp(plaintext, out, 8);                 // roundtrip
    box[32]++;                                           // make forgery
    status |= !crypto_anonymous_unlock(out, sk, box, 8); // reject forgery
    printf("%s: crypto_lock\n", status != 0 ? "FAILED" : "OK");
    return status;
}

int main(void)
{
    int status = 0;
    status |= generic_test(equal, "vectors_test_equal", 2);
    status |= generic_test(diff , "vectors_test_diff" , 2);
    status |= test(chacha20,  "vectors_chacha20", 2);
    status |= test(blake2b ,  "vectors_blake2b" , 2);
    status |= test(poly1305,  "vectors_poly1305", 2);
    status |= test(argon2i ,  "vectors_argon2i" , 6);
    status |= test(x25519  ,  "vectors_x25519"  , 2);
    status |= test(sha512  ,  "vectors_sha512"  , 1);
    status |= test(ed25519 ,  "vectors_ed25519" , 3);
    status |= test_x25519();
    status |= test_ae();
    status |= test_lock();
    printf(status ? "TESTS FAILED\n" : "ALL TESTS OK\n");
    return status;
}
