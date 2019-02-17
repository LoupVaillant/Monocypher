#include "speed.h"
#include "monocypher.h"
#include "sha512.h"
#include "utils.h"

static u64 chacha20(void)
{
    u8 out[SIZE];
    RANDOM_INPUT(in   , SIZE);
    RANDOM_INPUT(key  ,   32);
    RANDOM_INPUT(nonce,    8);

    TIMING_START {
        crypto_chacha_ctx ctx;
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_encrypt(&ctx, out, in, SIZE);
    }
    TIMING_END;
}

static u64 poly1305(void)
{
    u8 out[16];
    RANDOM_INPUT(in , SIZE);
    RANDOM_INPUT(key,   32);

    TIMING_START {
        crypto_poly1305(out, in, SIZE, key);
    }
    TIMING_END;
}

static u64 authenticated(void)
{
    u8 out[SIZE];
    u8 mac[  16];
    RANDOM_INPUT(in   , SIZE);
    RANDOM_INPUT(key  ,   32);
    RANDOM_INPUT(nonce,    8);

    TIMING_START {
        crypto_lock(mac, out, key, nonce, in, SIZE);
    }
    TIMING_END;
}

static u64 blake2b(void)
{
    u8 hash[64];
    RANDOM_INPUT(in , SIZE);
    RANDOM_INPUT(key,   32);

    TIMING_START {
        crypto_blake2b_general(hash, 64, key, 32, in, SIZE);
    }
    TIMING_END;
}

static u64 sha512(void)
{
    u8 hash[64];
    RANDOM_INPUT(in, SIZE);

    TIMING_START {
        crypto_sha512(hash, in, SIZE);
    }
    TIMING_END;
}

static u64 argon2i(void)
{
    u64    work_area[SIZE / 8];
    u8     hash     [32];
    size_t nb_blocks = SIZE / 1024;
    RANDOM_INPUT(password,  16);
    RANDOM_INPUT(salt    ,  16);

    TIMING_START {
        crypto_argon2i(hash, 32, work_area, nb_blocks, 3,
                       password, 16, salt, 16);
    }
    TIMING_END;
}

static u64 x25519(void)
{
    u8 in [32] = {9};
    u8 out[32] = {9};

    TIMING_START {
        if (crypto_x25519(out, out, in)) {
            printf("Monocypher x25519 rejected public key\n");
        }
    }
    TIMING_END;
}

static u64 edDSA_sign(void)
{
    u8 pk       [32];
    u8 signature[64];
    RANDOM_INPUT(sk     , 32);
    RANDOM_INPUT(message, 64);
    crypto_sign_public_key(pk, sk);

    TIMING_START {
        crypto_sign(signature, sk, pk, message, 64);
    }
    TIMING_END;
}

static u64 edDSA_check(void)
{
    u8 pk       [32];
    u8 signature[64];
    RANDOM_INPUT(sk     , 32);
    RANDOM_INPUT(message, 64);
    crypto_sign_public_key(pk, sk);
    crypto_sign(signature, sk, pk, message, 64);

    TIMING_START {
        if (crypto_check(signature, pk, message, 64)) {
            printf("Monocypher verification failed\n");
        }
    }
    TIMING_END;
}

int main()
{
    print("Chacha20         ",chacha20()     *MUL,"megabytes  per second");
    print("Poly1305         ",poly1305()     *MUL,"megabytes  per second");
    print("Auth'd encryption",authenticated()*MUL,"megabytes  per second");
    print("Blake2b          ",blake2b()      *MUL,"megabytes  per second");
    print("Sha512           ",sha512()       *MUL,"megabytes  per second");
    print("Argon2i, 3 passes",argon2i()      *MUL,"megabytes  per second");
    print("x25519           ",x25519()           ,"exchanges  per second");
    print("EdDSA(sign)      ",edDSA_sign()       ,"signatures per second");
    print("EdDSA(check)     ",edDSA_check()      ,"checks     per second");
    printf("\n");
    return 0;
}
