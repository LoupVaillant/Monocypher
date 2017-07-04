#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rename_monocypher.h"
#include "rename_sha512.h"
#include <sodium.h>

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
typedef uint8_t u8;

// Deterministic "random" number generator, so we can make "random", yet
// reproducible tests.  To change the random stream, change the seed.
void random(u8 *stream, u8 size)
{
    static rename_chacha_ctx ctx;
    static int is_init = 0;
    if (!is_init) {
        static const u8 seed[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
                                    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        rename_chacha20_init(&ctx, seed, seed);
        is_init = 1;
    }
    rename_chacha20_stream(&ctx, stream, size);
}

static int chacha20(void)
{
    u8  key[32], nonce[8], in[256], mono[256], sodium[256];
    int status = 0;
    FOR (size, 0, 256) FOR(i, 0, 10) {
        random(key, 32);
        random(nonce, 8);
        random(in, size);
        rename_chacha_ctx ctx;
        rename_chacha20_init(&ctx, key, nonce);
        rename_chacha20_encrypt(&ctx, mono, in, size);
        crypto_stream_chacha20_xor(sodium, in, size, nonce, key);
        status |= rename_memcmp(mono, sodium, size);
    }
    printf("%s: Chacha20\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int poly1305(void)
{
    u8 key[32], in[256], mono[16], sodium[16];
    int status = 0;
    FOR (size, 0, 256)  FOR(i, 0, 10) {
        random(key, 32);
        random(in, size);
        rename_poly1305_auth(mono, in, size, key);
        crypto_onetimeauth(sodium, in, size, key);
        status |= rename_memcmp(mono, sodium, 16);
    }
    printf("%s: Poly1305\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int blake2b(void)
{
    u8 key[32], in[256], mono[64], sodium[64];
    int status = 0;
    FOR (size, 0, 256)  FOR(key_size, 0, 32) FOR(hash_size, 1, 64) {
        random(key ,  key_size);
        random(in  ,      size);
        rename_blake2b_general(mono, hash_size, key, key_size, in, size);
        crypto_generichash(sodium,   hash_size, in, size, key, key_size);
        status |= rename_memcmp(mono, sodium, hash_size);
    }
    printf("%s: Blake2b\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int argon2i(void)
{
    u8 work_area[1024*1024], password[16], salt[crypto_pwhash_SALTBYTES],
        mono[32], sodium[32];
    int status = 0;
    FOR (nb_blocks, 8, 1024) {
        random(password, 16);
        random(salt    , 16);
        rename_argon2i(mono, 32, work_area, nb_blocks, 3,
                       password, crypto_pwhash_SALTBYTES, salt, 16, 0, 0, 0, 0);
        if (crypto_pwhash(sodium, 32, (char*)password, 16, salt,
                          3, nb_blocks * 1024, crypto_pwhash_ALG_DEFAULT)) {
            printf("Libsodium Argon2i failed to execute\n");
        }
        status |= rename_memcmp(mono, sodium, 32);
    }
    printf("%s: Argon2i\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int x25519()
{
    u8 sk1[32], pk1_mono[32], pk1_sodium[32];
    u8 sk2[32], pk2_mono[32], pk2_sodium[32];
    u8 shared_mono[32], shared_sodium[32];
    int status = 0;
    FOR (i, 0, 255) {
        random(sk1, 32);
        random(sk2, 32);
        rename_x25519_public_key(pk1_mono, sk1);
        rename_x25519_public_key(pk2_mono, sk2);
        crypto_scalarmult_base(pk1_sodium, sk1);
        crypto_scalarmult_base(pk2_sodium, sk2);
        rename_x25519    (shared_mono  , sk1, pk2_mono);
        if (crypto_scalarmult(shared_sodium, sk1, pk2_sodium)) {
            printf("Libsodium scalarmult rejected the public key\n");
        }
        status |= rename_memcmp(pk1_mono   , pk1_sodium, 32);
        status |= rename_memcmp(pk2_mono   , pk2_sodium, 32);
        status |= rename_memcmp(shared_mono, shared_sodium, 32);
    }
    printf("%s: x25519\n", status != 0 ? "FAILED" : "OK");
    return status;
}

static int ed25519()
{
    u8 sk[32], sk_sodium[64], pk_mono[32], pk_sodium[32];
    u8 msg[255], sig_mono[64], sig_sodium[64];
    int status = 0;
    FOR (size, 0, 255) {
        // public keys
        random(sk, 32);
        rename_sign_public_key(pk_mono, sk);
        crypto_sign_seed_keypair(pk_sodium, sk_sodium, sk);
        status |= rename_memcmp(pk_mono, pk_sodium, 32);
        // signatures
        random(msg, size);
        rename_sign(sig_mono, sk, pk_mono, msg, size);
        crypto_sign_detached(sig_sodium, 0, msg, size, sk_sodium);
        status |= rename_memcmp(sig_mono, sig_sodium, 64);
    }
    printf("%s: Ed25519\n", status != 0 ? "FAILED" : "OK");
    return status;
}


int main(void)
{
    if (sodium_init() == -1) {
        printf("Libsodium init failed.  Abort.  No test performed\n");
        return 1;
    }
    int status = 0;
    status |= chacha20();
    status |= poly1305();
    status |= blake2b();
    status |= argon2i();
    status |= x25519();
    status |= ed25519();
    return status;
}
