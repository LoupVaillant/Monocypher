#ifndef ARGON2I_H
#define ARGON2I_H

#include <inttypes.h>
#include <stddef.h>

// Implements argon2i, with degree of paralelism 1,
// because it's good enough, and threads are scary.
//
// key and ad are optionnal.  They can be NULL if their respective size is 0.
// work_area is a pointer to a contiguous chunk of memory of at least
// nb_blocks * 1024 bytes.  It must be suitably aligned for 64-bit words.
// Don't worry too much about alignment, malloc()'s results work.
//
// Choice of parameters for password hashing:
// - If you need a key, use a 32 bytes one.
// - Do what you will with the ad.
// - Use a 32 bytes tag (to get a 256-bit key)
// - Put 128 bits of entropy in the salt.  16 random bytes work well.
// - Use all the memory you can get away with.
// - Use as much iterations as reasonable.  No less than 10 passes if you can.
void
crypto_argon2i_hash(uint8_t       *tag,       uint32_t tag_size,      // >= 4
                    const uint8_t *password,  uint32_t password_size,
                    const uint8_t *salt,      uint32_t salt_size,     // >= 8
                    const uint8_t *key,       uint32_t key_size,
                    const uint8_t *ad,        uint32_t ad_size,
                    void    *work_area,
                    uint32_t nb_blocks,                               // >= 8
                    uint32_t nb_iterations);

// Convenience function. No key, no ad, 64 bytes tag
void
crypto_argon2i(uint8_t        tag[32],
               const uint8_t *password,  uint32_t password_size,
               const uint8_t *salt,      uint32_t salt_size,     // >= 8
               void    *work_area,
               uint32_t nb_blocks,                               // >= 8
               uint32_t nb_iterations);


#endif // ARGON2I_H
