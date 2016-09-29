#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include "chacha20.h"
#include "blake2b.h"
#include "poly1305.h"

/////////////////////////
/// General utilities ///
/////////////////////////
static void*
alloc(size_t size)
{
    void *buffer = malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Allocation failed\n");
        exit(1);
    }
    return buffer;
}

static FILE*
file_open(char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Could not open file %s", filename);
        exit(1);
    }
    return file;
}

static unsigned
uint_of_char(unsigned char c)
{
    if (c >= '0' && c <= '9') { return c - '0';      }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    fprintf(stderr, "'%c' (%d): Not a hexadecimal char\n", c, c);
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

static vector
vec_new(size_t buf_size)
{
    vector v;
    v.buffer   = alloc(buf_size);
    v.buf_size = buf_size;
    v.size = 0;
    return v;
}

static vector
vec_uninitialized(size_t size)
{
    vector v = vec_new(size);
    v.size = size;
    return v;
}

static vector
vec_zero(size_t size)
{
    vector v = vec_uninitialized(size);
    memset(v.buffer, 0, size);
    return v;
}

static void
vec_del(vector *v)
{
    free(v->buffer);
}

static void
vec_push_back(vector *v, uint8_t e)
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

// Read a line into a vector
// Free the vector's memory with vec_del()
static vector
read_hex_line(FILE *input_file)
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

////////////////////////
/// The tests proper ///
////////////////////////
static int
test_chacha20(char* filename)
{
    int   status = 0;
    FILE *file   = file_open(filename);
    while (getc(file) != EOF) {
        vector key    = read_hex_line(file);
        vector nonce  = read_hex_line(file);
        vector stream = read_hex_line(file);
        vector out    = vec_zero(stream.size);

        crypto_chacha_ctx ctx;
        crypto_init_chacha20(&ctx, key.buffer, nonce.buffer);
        crypto_encrypt_chacha20(&ctx, out.buffer, out.buffer, out.size);
        status |= memcmp(out.buffer, stream.buffer, out.size);

        vec_del(&out);
        vec_del(&stream);
        vec_del(&nonce);
        vec_del(&key);
    }
    printf("%s: chacha20\n", status != 0 ? "FAILED" : "OK");
    fclose(file);
    return status;
}

static int
test_blake2b(char* filename)
{
    int   status = 0;
    FILE *file   = file_open(filename);
    while (getc(file) != EOF) {
        vector in   = read_hex_line(file);
        vector key  = read_hex_line(file);
        vector hash = read_hex_line(file);
        vector out  = vec_uninitialized(hash.size);

        crypto_general_blake2b(out.buffer, hash.size,
                               key.buffer, key .size,
                               in .buffer, in  .size);
        status |= memcmp(out.buffer, hash.buffer, out.size);

        vec_del(&out);
        vec_del(&hash);
        vec_del(&key);
        vec_del(&in);
    }
    printf("%s: blake2b\n", status != 0 ? "FAILED" : "OK");
    fclose(file);
    return status;
}

static int
test_poly1305(char *filename)
{
    int   status = 0;
    FILE *file   = file_open(filename);
    while (getc(file) != EOF) {
        vector key = read_hex_line(file);
        vector msg = read_hex_line(file);
        vector tag = read_hex_line(file);
        vector out = vec_uninitialized(tag.size);

        crypto_poly1305_auth(out.buffer, msg.buffer, msg.size, key.buffer);
        status |= memcmp(out.buffer, tag.buffer, out.size);

        vec_del(&out);
        vec_del(&tag);
        vec_del(&msg);
        vec_del(&key);
    }
    printf("%s: poly1305\n", status != 0 ? "FAILED" : "OK");
    fclose(file);
    return status;
}

int main(void)
{
    int status = 0;
    status |= test_chacha20("vectors_chacha20.txt");
    status |= test_blake2b ("vectors_blake2b.txt" );
    status |= test_poly1305("vectors_poly1305.txt");
    return status;
}
