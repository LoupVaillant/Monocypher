#include "speed.h"
#include "sodium.h"

static u64 chacha20(void)
{
    static u8  in   [SIZE];  p_random(in   , SIZE);
    static u8  key  [  32];  p_random(key  ,   32);
    static u8  nonce[   8];  p_random(nonce,    8);
    static u8  out  [SIZE];

    TIMING_START {
        crypto_stream_chacha20_xor(out, in, SIZE, nonce, key);
    }
    TIMING_END;
}

static u64 poly1305(void)
{
    static u8  in [SIZE];  p_random(in   , SIZE);
    static u8  key[  32];  p_random(key  ,   32);
    static u8  out[  16];

    TIMING_START {
        crypto_onetimeauth(out, in, SIZE, key);
    }
    TIMING_END;
}

static u64 authenticated(void)
{
    static u8  in   [SIZE];  p_random(in   , SIZE);
    static u8  key  [  32];  p_random(key  ,   32);
    static u8  nonce[   8];  p_random(nonce,    8);
    static u8  out  [SIZE];
    static u8  mac  [crypto_aead_xchacha20poly1305_ietf_ABYTES];
    TIMING_START {
        crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
    }
    TIMING_END;
}

static u64 blake2b(void)
{
    static u8 in  [SIZE];  p_random(in , SIZE);
    static u8 key [  32];  p_random(key,   32);
    static u8 hash[  64];

    TIMING_START {
        crypto_generichash(hash, 64, in, SIZE, key, 32);
    }
    TIMING_END;
}

static u64 sha512(void)
{
    static u8 in  [SIZE];  p_random(in , SIZE);
    static u8 hash[  64];

    TIMING_START {
        crypto_hash_sha512(hash, in, SIZE);
    }
    TIMING_END;
}

static u64 argon2i(void)
{
    static u8 password [  16];  p_random(password, 16);
    static u8 salt     [  16];  p_random(salt    , 16);
    static u8 hash     [  32];

    TIMING_START {
        if (crypto_pwhash(hash, 32, (char*)password, 16, salt,
                          3, SIZE, crypto_pwhash_ALG_ARGON2I13)) {
            fprintf(stderr, "Argon2i failed.\n");
        }
    }
    TIMING_END;
}

static u64 x25519(void)
{
    u8 in [32] = {9};
    u8 out[32] = {9};

    TIMING_START {
        if (crypto_scalarmult(out, out, in)) {
            fprintf(stderr, "Libsodium rejected the public key\n");
        }
    }
    TIMING_END;
}

static u64 edDSA_sign(void)
{
    u8 sk       [64];  p_random(sk, 32);
    u8 pk       [32];  crypto_sign_keypair(pk, sk);
    u8 message  [64];  p_random(message, 64);
    u8 signature[64];

    TIMING_START {
        crypto_sign_detached(signature, 0, message, 64, sk);
    }
    TIMING_END;
}

static u64 edDSA_check(void)
{
    u8 sk       [64];  p_random(sk, 32);
    u8 pk       [32];  crypto_sign_keypair(pk, sk);
    u8 message  [64];  p_random(message, 64);
    u8 signature[64];

    crypto_sign_detached(signature, 0, message, 64, sk);

    TIMING_START {
        if (crypto_sign_verify_detached(signature, message, 64, pk)) {
            printf("Monocypher verification failed\n");
        }
    }
    TIMING_END;
}

int main()
{
    SODIUM_INIT;
    print("Chacha20         ", chacha20()      * MULT/DIV, "Mb/s"            );
    print("Poly1305         ", poly1305()      * MULT/DIV, "Mb/s"            );
    print("Auth'd encryption", authenticated() * MULT/DIV, "Mb/s"            );
    print("Blake2b          ", blake2b()       * MULT/DIV, "Mb/s"            );
    print("Sha512           ", sha512()        * MULT/DIV, "Mb/s"            );
    print("Argon2i          ", argon2i()       * MULT/DIV, "Mb/s (3 passes)" );
    print("x25519           ", x25519()        / DIV, "exchanges  per second");
    print("EdDSA(sign)      ", edDSA_sign()    / DIV, "signatures per second");
    print("EdDSA(check)     ", edDSA_check()   / DIV, "checks     per second");
    printf("\n");
    return 0;
}
