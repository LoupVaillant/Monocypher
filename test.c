#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "monocypher.h"
#include "sha512.h"

#define FOR(i, start, end) for (size_t i = start; i < end; i++)
#define sv static void
typedef  int8_t   i8;
typedef uint8_t   u8;
typedef uint32_t u32;
typedef  int32_t i32;
typedef  int64_t i64;
typedef uint64_t u64;

/////////////////////////
/// General utilities ///
/////////////////////////

static void* alloc(size_t size)
{
    void *buf = malloc(size);
    if (buf == NULL) {
        fprintf(stderr, "Allocation failed\n");
        exit(1);
    }
    return buf;
}

static int is_digit(int c)
{
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'A' && c <= 'F');
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

////////////////////////////////
/// File streams with lookup ///
////////////////////////////////
typedef struct { FILE *file; int head; int valid; } stream;

sv stream_open(stream *s, const char *filename)
{
    s->file  = fopen(filename, "r");
    s->valid = 0;
    if (s->file == NULL) {
        fprintf(stderr, "Could not open file %s", filename);
        exit(1);
    }
}
sv stream_close(stream *s) { fclose(s->file); }

static int stream_peek(stream *s)
{
    if (!s->valid) {
        s-> valid = 1;
        s-> head  = getc(s->file);
    }
    return s->head;
}

static int stream_get(stream *s)
{
    char c = stream_peek(s);
    s->valid = 0;
    return c;
}

sv stream_drop(stream *s)
{
    stream_get(s);
}

////////////////////////
/// Vector of octets ///
////////////////////////
typedef struct {
    uint8_t *buf;
    size_t   buf_size;
    size_t   size;
} vector;

static vector vec_new(size_t buf_size)
{
    vector v;
    v.buf      = (uint8_t*)alloc(buf_size);
    v.buf_size = buf_size;
    v.size     = 0;
    return v;
}

static vector vec_uninitialized(size_t size)
{
    vector v = vec_new(size);
    v.size = size;
    return v;
}

sv vec_del(vector *v)
{
    free(v->buf);
}

sv vec_push_back(vector *v, uint8_t e)
{
    if (v->buf_size == v->size) {
        // double initial buffer size (and then some)
        size_t   new_buf_size = v->buf_size * 2 + 1;
        uint8_t *new_buf   = (uint8_t*)alloc(new_buf_size);
        memcpy(new_buf, v->buf, v->buf_size);
        free(v->buf);
        v->buf   = new_buf;
        v->buf_size = new_buf_size;
    }
    v->buf[v->size] = e;
    v->size++;
}

static int vec_cmp(const vector *u, const vector *v)
{
    if (u->size != v-> size)
        return -1;
    return crypto_memcmp(u->buf, v->buf, u->size);
}

sv next_number(stream *s)
{
    while (stream_peek(s) != EOF &&
           stream_peek(s) != ':' &&
           !is_digit(stream_peek(s)))
        stream_drop(s);
}

// Read a line into a vector.
// A vector file is a list of colon terminated hex numbers.
// Ignores any character between a column and the following digit.
// The user must free the vector's memory with vec_del()
static vector read_hex_line(stream *s)
{
    vector v = vec_new(64);
    next_number(s);
    while (stream_peek(s) != ':') {
        uint8_t msb = uint_of_char(stream_get(s));
        uint8_t lsb = uint_of_char(stream_get(s));
        vec_push_back(&v, lsb | (msb << 4));
    }
    stream_drop(s);
    next_number(s);
    return v;
}

/////////////////////////////
/// Test helper functions ///
/////////////////////////////

// Pulls some test vectors, feed it to f, get a status back
// The test fails if the status is not zero
static int generic_test(int (*f)(const vector[]),
                        const char * filename, size_t nb_vectors)
{
    int     status   = 0;
    vector *inputs   = (vector*)alloc(nb_vectors * sizeof(vector));
    int     nb_tests = 0;
    stream  stream;
    stream_open(&stream, filename);

    while (stream_peek(&stream) != EOF) {
        FOR (i, 0, nb_vectors) { inputs[i] = read_hex_line(&stream); }
        status |= f(inputs);
        FOR (i, 0, nb_vectors) { vec_del(inputs + i); }
        nb_tests++;
    }
    printf("%s %3d tests: %s\n",
           status != 0 ? "FAILED" : "OK", nb_tests, filename);
    free(inputs);
    stream_close(&stream);
    return status;
}

// Same, except f writes to a buffer.  If it's different than
// some expected result, the test fails.
static int test(void (*f)(const vector[], vector*),
                const char *filename, size_t nb_vectors)
{
    int     status   = 0;
    vector *inputs   = (vector*)alloc(nb_vectors * sizeof(vector));
    int     nb_tests = 0;
    stream  stream;
    stream_open(&stream, filename);

    while (stream_peek(&stream) != EOF) {
        FOR (i, 0, nb_vectors) { inputs[i] = read_hex_line(&stream); }

        vector expected = read_hex_line(&stream);
        vector output   = vec_uninitialized(expected.size);
        f(inputs, &output);
        status |= vec_cmp(&output, &expected);

        vec_del(&output);
        vec_del(&expected);
        FOR (i, 0, nb_vectors) { vec_del(inputs + i); }
        nb_tests++;
    }
    printf("%s %3d tests: %s\n",
           status != 0 ? "FAILED" : "OK", nb_tests, filename);
    free(inputs);
    stream_close(&stream);
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
sv chacha20(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *nonce = in + 1;
    crypto_chacha_ctx ctx;
    crypto_chacha20_init  (&ctx, key->buf, nonce->buf);
    crypto_chacha20_stream(&ctx, out->buf, out->size);
}

sv hchacha20(const vector in[], vector *out)
{
    const vector *key   = in;
    const vector *input = in + 1;
    crypto_chacha20_H(out->buf, key->buf, input->buf);
}

sv xchacha20(const vector in[], vector *out)
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

sv poly1305(const vector in[], vector *out)
{
    const vector *key = in;
    const vector *msg = in + 1;
    crypto_poly1305_auth(out->buf, msg->buf, msg->size, key->buf);
}

sv argon2i(const vector in[], vector *out)
{
        const vector *nb_blocks     = in;
        const vector *nb_iterations = in + 1;
        const vector *password      = in + 2;
        const vector *salt          = in + 3;
        const vector *key           = in + 4;
        const vector *ad            = in + 5;
        void         *work_area     = alloc(nb_blocks->buf[0] * 1024);
        crypto_argon2i(out     ->buf, out     ->size,
                       password->buf, password->size,
                       salt    ->buf, salt    ->size,
                       key     ->buf, key     ->size,
                       ad      ->buf, ad      ->size,
                       work_area,
                       nb_blocks    ->buf[0],
                       nb_iterations->buf[0]);
        free(work_area);
}

sv x25519(const vector in[], vector *out)
{
    const vector *scalar = in;
    const vector *point  = in + 1;
    crypto_x25519(out->buf, scalar->buf, point->buf);
}

// Disabling the following test, because it takes too damn long
// I suggest you run it once, though.
sv iterate_x25519(uint8_t k[32], uint8_t u[32])
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
    int status = crypto_memcmp(k, _1, 32);
    printf("%s: x25519 1\n", status != 0 ? "FAILED" : "OK");

    uint8_t _1k  [32] = {0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
                         0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
                         0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
                         0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51};
    FOR (i, 1, 1000) { iterate_x25519(k, u); }
    status |= crypto_memcmp(k, _1k, 32);
    printf("%s: x25519 1K\n", status != 0 ? "FAILED" : "OK");

    // too long; didn't run
    //uint8_t _100k[32] = {0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd,
    //                     0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f,
    //                     0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf,
    //                     0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24};
    // FOR (i, 1000, 1000000) { iterate_x25519(k, u); }
    //status |= crypto_memcmp(k, _100k, 32);
    //printf("%s: x25519 1M\n", status != 0 ? "FAILED" : "OK");
    return status;
}

sv sha512(const vector in[], vector *out)
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
    const vector *msg    = in + 2;

    // Test that signature matches the test vector (out->buf).
    // Both signature modes must yield the same signature.
    u8 signature[64];
    crypto_sign(out->buf , secret_k->buf, 0          , msg->buf, msg->size);
    crypto_sign(signature, secret_k->buf, public_k->buf, msg->buf, msg->size);
    if (crypto_memcmp(signature, out->buf, 64)) {
        printf("FAILURE: signature modes yield different signatures!\n");
    }

    // test successful signature verification
    if (crypto_check(out->buf, public_k->buf, msg->buf, msg->size)) {
        printf("FAILURE: signature check failed to recognise signature\n");
    }
    // test forgery rejections
    uint8_t fake_signature1[64];
    uint8_t fake_signature2[64];
    FOR (i, 0, 64) {
        fake_signature1[i] = out->buf[i] + 1;
        fake_signature2[i] = out->buf[i] + 1;
    }
    if (!crypto_check(fake_signature1, public_k->buf, msg->buf, msg->size) ||
        !crypto_check(fake_signature2, public_k->buf, msg->buf, msg->size)) {
        printf("FAILURE: signature check failed to reject forgery\n");
    }
}

static int test_aead()
{
    uint8_t key[32]      = { 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
                             0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7 };
    uint8_t nonce[24]    = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                             1, 1, 1, 1, 1, 1, 1, 1 };
    uint8_t ad       [4] = { 3, 2, 1, 0 };
    uint8_t plaintext[8] = { 7, 6, 5, 4, 3, 2, 1, 0 };
    uint8_t box[24];
    uint8_t out[8];
    int status = 0;
    crypto_lock(box, key, nonce, plaintext, 8);           // make true message
    status |= crypto_unlock(out, key, nonce, box, 8+16);  // accept true message
    status |= crypto_memcmp(plaintext, out, 8);           // roundtrip
    box[0]++;                                             // make forgery
    status |= !crypto_unlock(out, key, nonce, box, 8+16); // reject forgery
    printf("%s: aead\n", status != 0 ? "FAILED" : "OK");

    crypto_aead_lock(box, box+16, key, nonce, ad, 4, plaintext, 8);
    status |= crypto_aead_unlock(out, key, nonce, box, ad, 4, box+16, 8);
    status |= crypto_memcmp(plaintext, out, 8);
    box[0]++;
    status |= !crypto_aead_unlock(out, key, nonce, box, ad, 4, box+16, 8);
    printf("%s: aead (simplified)\n", status != 0 ? "FAILED" : "OK");

    return status;
}

int main(void)
{
    int status = 0;
    status |= generic_test(equal, "vectors_test_equal"  , 2);
    status |= generic_test(diff , "vectors_test_diff"   , 2);
    status |= test(chacha20     , "vectors_chacha20"    , 2);
    status |= test(hchacha20    , "vectors_h_chacha20"  , 2);
    status |= test(xchacha20    , "vectors_x_chacha20"  , 2);
    status |= test(blake2b      , "vectors_blake2b"     , 2);
    status |= test(poly1305     , "vectors_poly1305"    , 2);
    status |= test(argon2i      , "vectors_argon2i"     , 6);
    status |= test(x25519       , "vectors_x25519"      , 2);
    status |= test(sha512       , "vectors_sha512"      , 1);
    status |= test(ed25519_key  , "vectors_ed25519_key" , 1);
    status |= test(ed25519_sign , "vectors_ed25519_sign", 3);
    status |= test_x25519();
    status |= test_aead();
    printf(status ? "TESTS FAILED\n" : "ALL TESTS OK\n");
    return status;
}
