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

static void get_interactive_session(u8 msg1[32], u8 msg2[48], u8 msg3[48],
                                    u8 client_pk[32], u8 server_pk[32],
                                    const u8 client_sk  [32],
                                    const u8 server_sk  [32],
                                    const u8 client_seed[32],
                                    const u8 server_seed[32])
{
    crypto_key_exchange_public_key(client_pk, client_sk);
    crypto_key_exchange_public_key(server_pk, server_sk);

    u8 c_seed[32];
    u8 s_seed[32];
    FOR (i, 0, 32) {
        c_seed[i] = client_seed[i];
        s_seed[i] = server_seed[i];
    }
    crypto_kex_client_ctx client_ctx;
    crypto_kex_xk1_init_client(&client_ctx, c_seed, client_sk, client_pk,
                               server_pk);
    crypto_kex_server_ctx server_ctx;
    crypto_kex_xk1_init_server(&server_ctx, s_seed, server_sk, server_pk);

    crypto_kex_xk1_1(&client_ctx, msg1);
    crypto_kex_xk1_2(&server_ctx, msg2, msg1);

    u8 client_session_key[32];
    if (crypto_kex_xk1_3(&client_ctx, client_session_key,
                         msg3, msg2)) {
        fprintf(stderr, "Cannot confirm\n");
        return;
    }

    u8 server_session_key[32];
    u8 remote_pk         [32]; // same as client_pk
    if (crypto_kex_xk1_4(&server_ctx, server_session_key, remote_pk,
                         msg3)) {
        fprintf(stderr, "Cannot accept\n");
        return;
    }

    if (crypto_verify32(client_session_key, server_session_key)) {
        fprintf(stderr, "Different session keys\n");
        return;
    }
    if (crypto_verify32(remote_pk, client_pk)) {
        fprintf(stderr, "Server got the wrong client public key\n");
        return;
    }
}


static u64 interactive_client(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    u8 msg1[32]; u8 msg2[48]; u8 msg3[48];
    u8 client_pk[32]; u8 server_pk[32];
    get_interactive_session(msg1, msg2, msg3,
                            client_pk  , server_pk,
                            client_sk  , server_sk,
                            client_seed, server_seed);
    TIMING_START {
        u8 session_key[32];
        crypto_kex_client_ctx client_ctx;
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = client_seed[i];
        }
        crypto_kex_xk1_init_client(&client_ctx, seed, client_sk, client_pk,
                                   server_pk);
        crypto_kex_xk1_1(&client_ctx, msg1);
        if (crypto_kex_xk1_3(&client_ctx, session_key,
                             msg3, msg2)) {
            fprintf(stderr, "Cannot confirm\n");
            return 1;
        }
    }
    TIMING_END;
}

static u64 interactive_server(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    RANDOM_INPUT(server_seed, 32);
    u8 msg1[32]; u8 msg2[48]; u8 msg3[48];
    u8 client_pk[32]; u8 server_pk[32];
    get_interactive_session(msg1, msg2, msg3,
                            client_pk  , server_pk,
                            client_sk  , server_sk,
                            client_seed, server_seed);
    TIMING_START {
        u8 session_key[32];
        u8 remote_pk         [32]; // same as client_pk
        crypto_kex_server_ctx server_ctx;
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = server_seed[i];
        }
        crypto_kex_xk1_init_server(&server_ctx, seed, server_sk, server_pk);
        crypto_kex_xk1_2(&server_ctx, msg2, msg1);
        if (crypto_kex_xk1_4(&server_ctx, session_key, remote_pk,
                             msg3)) {
            fprintf(stderr, "Cannot accept\n");
            return 1;
        }
    }
    TIMING_END;
}

static void get_one_way_session(u8 msg[80], u8 client_pk[32], u8 server_pk[32],
                                const u8 client_sk  [32],
                                const u8 server_sk  [32],
                                const u8 client_seed[32])
{
    crypto_key_exchange_public_key(client_pk, client_sk);
    crypto_key_exchange_public_key(server_pk, server_sk);

    u8 c_seed[32];
    FOR (i, 0, 32) {
        c_seed[i] = client_seed[i];
    }

    crypto_kex_client_ctx client_ctx;
    crypto_kex_x_init_client(&client_ctx, c_seed, client_sk, client_pk,
                             server_pk);
    crypto_kex_server_ctx server_ctx;
    crypto_kex_x_init_server(&server_ctx, server_sk, server_pk);

    u8 client_session_key[32];
    crypto_kex_x_1(&client_ctx, client_session_key, msg);

    u8 server_session_key[32];
    u8 remote_pk         [32]; // same as client_pk
    if (crypto_kex_x_2(&server_ctx, server_session_key, remote_pk, msg)) {
        fprintf(stderr, "Cannot receive\n");
        return;
    }

    if (crypto_verify32(client_session_key, server_session_key)) {
        fprintf(stderr, "Different session keys\n");
        return;
    }
    if (crypto_verify32(remote_pk, client_pk)) {
        fprintf(stderr, "Server got the wrong client public key\n");
        return;
    }
}

static u64 one_way_client(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    u8 msg[80]; u8 client_pk[32]; u8 server_pk[32];
    get_one_way_session(msg,
                        client_pk, server_pk,
                        client_sk, server_sk,
                        client_seed);
    TIMING_START {
        u8 session_key[32];
        u8 seed[32];
        FOR (i, 0, 32) {
            seed[i] = client_seed[i];
        }
        crypto_kex_client_ctx client_ctx;
        crypto_kex_x_init_client(&client_ctx, seed, client_sk, client_pk,
                                 server_pk);
        crypto_kex_x_1(&client_ctx, session_key, msg);
    }
    TIMING_END;
}

static u64 one_way_server(void)
{
    RANDOM_INPUT(client_sk, 32);
    RANDOM_INPUT(server_sk, 32);
    RANDOM_INPUT(client_seed, 32);
    u8 msg[80]; u8 client_pk[32]; u8 server_pk[32];
    get_one_way_session(msg,
                        client_pk, server_pk,
                        client_sk, server_sk,
                        client_seed);
    TIMING_START {
        u8 session_key[32];
        u8 remote_pk         [32]; // same as client_pk
        crypto_kex_server_ctx server_ctx;
        crypto_kex_x_init_server(&server_ctx, server_sk, server_pk);
        if (crypto_kex_x_2(&server_ctx, session_key, remote_pk, msg)) {
            fprintf(stderr, "Cannot receive\n");
            return 1;
        }
    }
    TIMING_END;
}

int main()
{
    print("Chacha20            ",chacha20()     *MUL ,"megabytes  per second");
    print("Poly1305            ",poly1305()     *MUL ,"megabytes  per second");
    print("Auth'd encryption   ",authenticated()*MUL ,"megabytes  per second");
    print("Blake2b             ",blake2b()      *MUL ,"megabytes  per second");
    print("Sha512              ",sha512()       *MUL ,"megabytes  per second");
    print("Argon2i, 3 passes   ",argon2i()      *MUL ,"megabytes  per second");
    print("x25519              ",x25519()            ,"exchanges  per second");
    print("EdDSA(sign)         ",edDSA_sign()        ,"signatures per second");
    print("EdDSA(check)        ",edDSA_check()       ,"checks     per second");
    print("Monokex XK1 (client)",interactive_client(),"handshakes per second");
    print("Monokex XK1 (server)",interactive_server(),"handshakes per second");
    print("Monokex X   (client)",one_way_client()    ,"handshakes per second");
    print("Monokex X   (server)",one_way_server()    ,"handshakes per second");
    printf("\n");
    return 0;
}
