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

static u64 chacha20_block(size_t size)
{
    static u8  in   [4096];  p_random(in   , size);
    static u8  key  [  32];  p_random(key  ,   32);
    static u8  nonce[   8];  p_random(nonce,    8);
    static u8  out  [4096];

    TIMING_START {
        FOR (i, 0, SIZE / size) {
            crypto_stream_chacha20_xor(out, in, size, nonce, key);
        }
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

static u64 poly1305_block(size_t size)
{
    static u8  in [4096];  p_random(in   , size);
    static u8  key[  32];  p_random(key  ,   32);
    static u8  out[  16];

    TIMING_START {
        FOR(i, 0, SIZE / size) {
            crypto_onetimeauth(out, in, size, key);
        }
    }
    TIMING_END;
}

void mono(uint8_t        mac[16],
          uint8_t       *cipher_text,
          const uint8_t  key[32],
          const uint8_t  nonce[24],
          const uint8_t *ad        , size_t ad_size,
          const uint8_t *plain_text, size_t text_size)
{
    u8 auth_key[64];
    crypto_stream_chacha20(auth_key, 64, nonce, key);
    if (text_size >= 32) {
        for (int i = 0; i < 32; i += 8) {
            store64_le(cipher_text + i,
                       load64_le(auth_key + 32 + i) ^
                       load64_le(plain_text    + i));
        }
        crypto_stream_xchacha20_xor_ic(cipher_text + 32, plain_text,
                                       text_size - 32, nonce, 1, key);
    } else {
        FOR (i, 0, text_size) {
            cipher_text[i] = plain_text[i] ^ auth_key[i+32];
        }
    }
    crypto_onetimeauth_state ctx;
    crypto_onetimeauth_init  (&ctx, auth_key);
    crypto_onetimeauth_update(&ctx, ad         , ad_size    );
    crypto_onetimeauth_update(&ctx, cipher_text, text_size  );
    crypto_onetimeauth_final (&ctx, mac);
}

void ietf(uint8_t        mac[16],
          uint8_t       *cipher_text,
          const uint8_t  key[32],
          const uint8_t  nonce[24],
          const uint8_t *ad        , size_t ad_size,
          const uint8_t *plain_text, size_t text_size)
{
    u8 auth_key[64];
    crypto_stream_chacha20(auth_key, 64, nonce, key);
    crypto_stream_xchacha20_xor_ic(cipher_text, plain_text, text_size,
                                   nonce, 1, key);
    u8 padding[15] = {0};
    u8 sizes  [16];
    unsigned p_ad_size   = (-  ad_size) & 15;
    unsigned p_text_size = (-text_size) & 15;
    store64_le(sizes    ,   ad_size);
    store64_le(sizes + 8, text_size);

    crypto_onetimeauth_state ctx;
    crypto_onetimeauth_init  (&ctx, auth_key);
    crypto_onetimeauth_update(&ctx, ad         , ad_size    );
    crypto_onetimeauth_update(&ctx, padding    , p_ad_size  );
    crypto_onetimeauth_update(&ctx, cipher_text, text_size  );
    crypto_onetimeauth_update(&ctx, padding    , p_text_size);
    crypto_onetimeauth_update(&ctx, sizes      , 16         );
    crypto_onetimeauth_final (&ctx, mac);
}


static u64 authenticated(void (*f)(uint8_t[16], uint8_t*,
                                   const uint8_t[32], const uint8_t[24],
                                   const uint8_t*, size_t,
                                   const uint8_t*, size_t))
{
    static u8  in   [SIZE];  p_random(in   , SIZE);
    static u8  key  [  32];  p_random(key  ,   32);
    static u8  nonce[   8];  p_random(nonce,    8);
    static u8  out  [SIZE];
    static u8  mac  [crypto_aead_xchacha20poly1305_ietf_ABYTES];
    TIMING_START {
        //crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
        //    out, mac, 0, in, SIZE, 0, 0, 0, nonce, key);
        f(mac, out, key, nonce, 0, 0, in, SIZE);
    }
    TIMING_END;
}

static u64 auth_block(size_t size,
                      void (*f)(uint8_t[16], uint8_t*,
                                const uint8_t[32], const uint8_t[24],
                                const uint8_t*, size_t,
                                const uint8_t*, size_t))
{
    static u8  in   [4096];  p_random(in   , size);
    static u8  key  [  32];  p_random(key  ,   32);
    static u8  nonce[   8];  p_random(nonce,    8);
    static u8  out  [4096];
    static u8  mac  [crypto_aead_xchacha20poly1305_ietf_ABYTES];
    TIMING_START {
        FOR (i, 0, SIZE/ size) {
            //crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            //    out, mac, 0, in, size, 0, 0, 0, nonce, key);
            f(mac, out, key, nonce, 0, 0, in, size);
        }
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
    print("Chacha20           ",chacha20()           /DIV,"megabytes ");
    print("  4k blocks        ",chacha20_block(4096) /DIV,"megabytes ");
    print("  2k blocks        ",chacha20_block(2048) /DIV,"megabytes ");
    print("  1k blocks        ",chacha20_block(1024) /DIV,"megabytes ");
    print("Poly1305           ",poly1305()           /DIV,"megabytes ");
    print("  4k blocks        ",poly1305_block(4096) /DIV,"megabytes ");
    print("  2k blocks        ",poly1305_block(2048) /DIV,"megabytes ");
    print("  1k blocks        ",poly1305_block(1024) /DIV,"megabytes ");
    print("Auth'd encryption  ",authenticated(ietf)  /DIV,"megabytes ");
    print("  4k   blocks      ",auth_block(4096,ietf)/DIV,"megabytes ");
    print("  4k   blocks mono ",auth_block(4096,mono)/DIV,"megabytes ");
    print("  2k   blocks      ",auth_block(2048,ietf)/DIV,"megabytes ");
    print("  2k   blocks mono ",auth_block(2048,mono)/DIV,"megabytes ");
    print("  1k   blocks      ",auth_block(1024,ietf)/DIV,"megabytes ");
    print("  1k   blocks mono ",auth_block(1024,mono)/DIV,"megabytes ");
    print("  512b blocks      ",auth_block( 512,ietf)/DIV,"megabytes ");
    print("  512b blocks mono ",auth_block( 512,mono)/DIV,"megabytes ");
    print("Blake2b            ",blake2b()            /DIV,"megabytes ");
    print("Sha512             ",sha512()             /DIV,"megabytes ");
    print("Argon2i, 3 passes  ",argon2i()            /DIV,"megabytes ");
    print("x25519             ",x25519()                 ,"exchanges ");
    print("EdDSA(sign)        ",edDSA_sign()             ,"signatures");
    print("EdDSA(check)       ",edDSA_check()            ,"checks    ");
    printf("\n");
    return 0;
}
