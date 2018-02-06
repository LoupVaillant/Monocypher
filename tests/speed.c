#include "speed.h"
#include "monocypher.h"
#include "sha512.h"
#include "utils.h"


static u64 chacha20(void)
{
    static u8  in   [SIZE];  p_random(in   , SIZE);
    static u8  key  [  32];  p_random(key  ,   32);
    static u8  nonce[   8];  p_random(nonce,    8);
    static u8  out  [SIZE];

    TIMING_START {
        crypto_chacha_ctx ctx;
        crypto_chacha20_init(&ctx, key, nonce);
        crypto_chacha20_encrypt(&ctx, out, in, SIZE);
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
            crypto_chacha_ctx ctx;
            crypto_chacha20_init(&ctx, key, nonce);
            crypto_chacha20_encrypt(&ctx, out, in, size);
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
        crypto_poly1305(out, in, SIZE, key);
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
            crypto_poly1305(out, in, size, key);
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
    crypto_chacha_ctx cctx;
    crypto_chacha20_init  (&cctx, key, nonce);
    crypto_chacha20_stream(&cctx, auth_key, 64);

    if (text_size >= 32) {
        for (int i = 0; i < 32; i += 8) {
            store64_le(cipher_text + i,
                       load64_le(auth_key + 32 + i) ^
                       load64_le(plain_text    + i));
        }
        crypto_chacha20_encrypt(&cctx, cipher_text + 32, plain_text,
                                text_size - 32);
    } else {
        FOR (i, 0, text_size) {
            cipher_text[i] = plain_text[i] ^ auth_key[i+32];
        }
    }
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, auth_key);
    crypto_poly1305_update(&ctx, ad         , ad_size  );
    crypto_poly1305_update(&ctx, cipher_text, text_size);
    crypto_poly1305_final (&ctx, mac);
}

void ietf(uint8_t        mac[16],
          uint8_t       *cipher_text,
          const uint8_t  key[32],
          const uint8_t  nonce[24],
          const uint8_t *ad        , size_t ad_size,
          const uint8_t *plain_text, size_t text_size)
{
    u8 auth_key[64];
    crypto_chacha_ctx cctx;
    crypto_chacha20_init   (&cctx, key, nonce);
    crypto_chacha20_stream (&cctx, auth_key, 64);
    crypto_chacha20_encrypt(&cctx, cipher_text, plain_text, text_size);

    u8 padding[15] = {0};
    u8 sizes  [16];
    unsigned p_ad_size   = (-  ad_size) & 15;
    unsigned p_text_size = (-text_size) & 15;
    store64_le(sizes    ,   ad_size);
    store64_le(sizes + 8, text_size);

    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, auth_key);
    crypto_poly1305_update(&ctx, ad         , ad_size    );
    crypto_poly1305_update(&ctx, padding    , p_ad_size  );
    crypto_poly1305_update(&ctx, cipher_text, text_size  );
    crypto_poly1305_update(&ctx, padding    , p_text_size);
    crypto_poly1305_update(&ctx, sizes      , 16         );
    crypto_poly1305_final (&ctx, mac);
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
    static u8  mac  [  16];

    TIMING_START {
        f(mac, out, key, nonce, 0, 0, in, SIZE);
        //crypto_lock(mac, out, key, nonce, in, SIZE);
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
    static u8  mac  [  16];
    static u8  out  [4096];

    TIMING_START {
        FOR (i, 0, SIZE / size) {
            f(mac, out, key, nonce, 0, 0, in, size);
            //crypto_lock(mac, out, key, nonce, in, size);
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
        crypto_blake2b_general(hash, 64, key, 32, in, SIZE);
    }
    TIMING_END;
}

static u64 sha512(void)
{
    static u8 in  [SIZE];  p_random(in , SIZE);
    static u8 hash[  64];

    TIMING_START {
        crypto_sha512(hash, in, SIZE);
    }
    TIMING_END;
}

static u64 argon2i(void)
{
    size_t    nb_blocks = SIZE / 1024;
    static u8 work_area[SIZE];
    static u8 password [  16];  p_random(password, 16);
    static u8 salt     [  16];  p_random(salt    , 16);
    static u8 hash     [  32];

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
    u8 sk       [32];  p_random(sk, 32);
    u8 pk       [32];  crypto_sign_public_key(pk, sk);
    u8 message  [64];  p_random(message, 64);
    u8 signature[64];

    TIMING_START {
        crypto_sign(signature, sk, pk, message, 64);
    }
    TIMING_END;
}

static u64 edDSA_check(void)
{
    u8 sk       [32];  p_random(sk, 32);
    u8 pk       [32];  crypto_sign_public_key(pk, sk);
    u8 message  [64];  p_random(message, 64);
    u8 signature[64];

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
