#ifndef UTILS_H
#define UTILS_H

#include <inttypes.h>
#include <stddef.h>

typedef int8_t   i8;
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

#define FOR(i, start, end) for (size_t i = (start); i < (end); i++)
#define SODIUM_INIT                                     \
    do {                                                \
        if (sodium_init() == -1) {                      \
            printf("Libsodium init failed.  Abort.\n"); \
            return 1;                                   \
        }                                               \
    } while (0)
#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)

extern u64 random_state; // state of the RNG

typedef struct {
    u8     *buf;
    size_t  size;
} vector;

void store64_le(u8 out[8], u64 in);
u64  load64_le(const u8 s[8]);
u32  load32_le(const u8 s[8]);
u64 rand64(); // Pseudo-random 64 bit number, based on xorshift*
void p_random(u8 *stream, size_t size);
void print_vector(const u8 *buf, size_t size);
void print_number(u64 n);
void* alloc(size_t size);

int vector_test(void (*f)(const vector[], vector*),
                const char *name, size_t nb_inputs,
                size_t nb_vectors, u8 **vectors, size_t *sizes);

#endif // UTILS_H
