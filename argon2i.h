#ifndef ARGON2I_H
#define ARGON2I_H

#include <inttypes.h>
#include <stddef.h>

// Implements argon2i, with degree of paralelism 1,
// because it's good enough, and threads are scary.
void
crypto_Argon2i_hash(uint8_t       *tag,       uint32_t tag_size,      // >= 4
                    const uint8_t *password,  uint32_t password_size,
                    const uint8_t *salt,      uint32_t salt_size,     // >= 8
                    const uint8_t *key,       uint32_t key_size,
                    const uint8_t *ad,        uint32_t ad_size,
                    void    *work_area,
                    uint32_t nb_blocks,                               // >= 8
                    uint32_t nb_iterations);



#endif // ARGON2I_H
