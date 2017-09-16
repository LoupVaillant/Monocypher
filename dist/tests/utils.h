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

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
#define SODIUM_INIT                                 \
    if (sodium_init() == -1) {                      \
        printf("Libsodium init failed.  Abort.\n"); \
        return 1;                                   \
    }
#define RANDOM_INPUT(name, size) u8 name[size]; p_random(name, size)

u64  load64_le(const u8 s[8]);
void p_random(u8 *stream, size_t size);
u64  rand64();
void print_vector(u8 *buf, size_t size);
void print_number(u64 n);

#endif // UTILS_H
