#include "utils.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void store64_le(u8 out[8], u64 in)
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
    out[4] = (in >> 32) & 0xff;
    out[5] = (in >> 40) & 0xff;
    out[6] = (in >> 48) & 0xff;
    out[7] = (in >> 56) & 0xff;
}

u64 load64_le(const u8 s[8])
{
    return (u64)s[0]
        | ((u64)s[1] <<  8)
        | ((u64)s[2] << 16)
        | ((u64)s[3] << 24)
        | ((u64)s[4] << 32)
        | ((u64)s[5] << 40)
        | ((u64)s[6] << 48)
        | ((u64)s[7] << 56);
}

// Must be seeded with a nonzero value.
// Accessible from the outside so we can modify it
u64 random_state = 12345;

// Pseudo-random 64 bit number, based on xorshift*
u64 rand64()
{
    random_state ^= random_state >> 12;
    random_state ^= random_state << 25;
    random_state ^= random_state >> 27;
    return random_state * 0x2545F4914F6CDD1D; // magic constant
}

void p_random(u8 *stream, size_t size)
{
    FOR (i, 0, size) {
        stream[i] = (u8)rand64();
    }
}

void print_vector(const u8 *buf, size_t size)
{
    FOR (i, 0, size) {
        printf("%x%x", buf[i] >> 4, buf[i] & 0x0f);
    }
    printf(":\n");
}

void print_number(u64 n)
{
    u8 buf[8];
    store64_le(buf, n);
    print_vector(buf, 8);
}



void* alloc(size_t size)
{
    if (size == 0) {
        // Some systems refuse to allocate zero bytes.
        // So we don't.  Instead, we just return a non-sensical pointer.
        // It shouldn't be dereferenced anyway.
        return NULL;
    }
    void *buf = malloc(size);
    if (buf == NULL) {
        fprintf(stderr, "Allocation failed: 0x%zx bytes\n", size);
        exit(1);
    }
    return buf;
}

int zerocmp(const u8 *p, size_t n)
{
    FOR (i, 0, n) {
        if (p[i] != 0) { return -1; }
    }
    return 0;
}

int vector_test(void (*f)(const vector[], vector*),
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

