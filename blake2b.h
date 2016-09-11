#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <inttypes.h>
#include <stddef.h>

// state context
typedef struct {
    uint8_t  b[128]; // input buffer
    uint64_t h[8];   // chained state
    uint64_t t[2];   // total number of bytes
    size_t   c;      // pointer for b[]
    size_t   outlen; // digest size
} crypto_blake2b_ctx;

// Initializes the context with user defined parameters:
// outlen: the length of the hash.  Must be between 1 and 64.
// keylen: length of the key.       Must be between 0 and 64.
// key   : some secret key.  May be NULL if keylen is 0.
// Any deviation from these invariants results in UNDEFINED BEHAVIOR
void
crypto_general_blake2b_init(crypto_blake2b_ctx *ctx, size_t outlen,
                            const void         *key, size_t keylen);

// Convenience function: 64 bytes hash, no secret key.
void
crypto_blake2b_init(crypto_blake2b_ctx *ctx);

// Add "inlen" bytes from "in" into the hash.
void
crypto_blake2b_update(crypto_blake2b_ctx *ctx, const void *in, size_t inlen);

// Generate the message digest (size given in init).
void
crypto_blake2b_final(crypto_blake2b_ctx *ctx, void *out);

// All-in-one convenience function.
void
crypto_general_blake2b(void       *out, size_t outlen, // digest
                       const void *key, size_t keylen, // optional secret key
                       const void *in , size_t inlen); // data to be hashed

// All-in-one convenience function: 64 bytes hash, no secret key.
void
crypto_blake2b(void *out, const void *in, size_t inlen);



#endif // BLAKE2B_H
