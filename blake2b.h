#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <inttypes.h>
#include <stddef.h>

// blake2b context
typedef struct {
    uint8_t  buf[128];      // input buffer
    uint64_t hash[8];       // chained state
    uint64_t input_size[2]; // total number of bytes
    uint8_t  c;             // pointer for buf[]
    uint8_t  output_size;   // digest size
} crypto_blake2b_ctx;

// Initializes the context with user defined parameters:
// outlen: the length of the hash.  Must be between 1 and 64.
// keylen: length of the key.       Must be between 0 and 64.
// key   : some secret key.         May be NULL if keylen is 0.
// Any deviation from these invariants results in UNDEFINED BEHAVIOR
void
crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t outlen,
                            const uint8_t      *key, size_t keylen);

// Convenience function: 64 bytes hash, no secret key.
void
crypto_blake2b_init(crypto_blake2b_ctx *ctx);

// Add "inlen" bytes from "in" into the hash.
void
crypto_blake2b_update(crypto_blake2b_ctx *ctx, const uint8_t *in, size_t inlen);

// Generate the message digest (size given in init).
void
crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *out);

// All-in-one convenience function.
// outlen, keylen, and key work the same as they do in the general_init function
void
crypto_blake2b_general(      uint8_t *out, size_t outlen, // digest
                       const uint8_t *key, size_t keylen, // optional secret key
                       const uint8_t *in , size_t inlen); // data to be hashed

// All-in-one convenience function: 64 bytes hash, no secret key.
void
crypto_blake2b(uint8_t out[64], const uint8_t *in, size_t inlen);



#endif // BLAKE2B_H
