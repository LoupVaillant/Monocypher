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

///////////////////////////
/// Test the test suite ///
///////////////////////////
static int meta(int (*f)(int), char *filename)
{
    int   status = 0;
    FILE *file   = file_open(filename);
    while (getc(file) != EOF) {
        vector a = read_hex_line(file);
        vector b = read_hex_line(file);
        status |= f(vec_cmp(&a, &b));
        vec_del(&b);
        vec_del(&a);
    }
    printf("%s: %s\n", status != 0 ? "FAILED" : "OK", filename);
    fclose(file);
    return status;
}
static int equal(int status) { return  status; }
static int diff (int status) { return !status; }

////////////////////////
/// The tests proper ///
////////////////////////
static int test(void (*f)(const vector[], vector*),
                char *filename, size_t nb_vectors)
{
    int     status = 0;
    FILE   *file   = file_open(filename);
    vector *inputs = alloc(nb_vectors * sizeof(vector));

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
    }
    printf("%s: %s\n", status != 0 ? "FAILED" : "OK", filename);
    free(inputs);
    fclose(file);
    return status;
}

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
    crypto_ae_lock(key, nonce, plaintext, 8, box);        // make true message
    status |= crypto_ae_unlock(key, nonce, box, 8, out);  // accept true message
    status |= memcmp(plaintext, out, 8);                  // roundtrip
    box[0]++;                                             // make forgery
    status |= !crypto_ae_unlock(key, nonce, box, 8, out); // reject forgery
    printf("%s: authenticated encryption\n", status != 0 ? "FAILED" : "OK");
    return status;
}

int main(void)
{
    int status = 0;
    status |= meta(equal,     "vectors_test_equal.txt" );
    status |= meta(diff,      "vectors_test_diff.txt"  );
    status |= test(chacha20,  "vectors_chacha20.txt", 2);
    status |= test(blake2b ,  "vectors_blake2b.txt" , 2);
    status |= test(poly1305,  "vectors_poly1305.txt", 2);
    status |= test(argon2i ,  "vectors_argon2i.txt" , 6);
    status |= test_ae();
    printf(status ? "TESTS FAILED\n" : "ALL TESTS OK\n");
    return status;
}
