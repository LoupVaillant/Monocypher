#include "speed.h"
#include "utils.h"
#include "hydrogen.h"

static u64 hydro_random(void)
{
    u8 out[SIZE];
    RANDOM_INPUT(key  ,   32);
    RANDOM_INPUT(nonce,    8);

    TIMING_START {
        hydro_random_buf_deterministic(out, SIZE, key);
    }
    TIMING_END;
}

static u64 authenticated(void)
{
    u8 out[SIZE + hydro_secretbox_HEADERBYTES];
    RANDOM_INPUT(in , SIZE + 32);
    RANDOM_INPUT(key,        32);
    TIMING_START {
        hydro_secretbox_encrypt(out, in, SIZE, 0, "Benchmark", key);
    }
    TIMING_END;
}

static u64 hash(void)
{
    u8 hash[32];
    RANDOM_INPUT(in, SIZE);

    TIMING_START {
        hydro_hash_hash(hash, 32, in, SIZE, "Benchmark", 0);
    }
    TIMING_END;
}

static u64 sign(void)
{
    RANDOM_INPUT(message, 64);
    hydro_sign_keypair key_pair;
    hydro_sign_keygen(&key_pair);
    uint8_t sig[hydro_sign_BYTES];

    TIMING_START {
        hydro_sign_create(sig, message, 64, "Benchmark", key_pair.sk);
    }
    TIMING_END;
}

static u64 check(void)
{
    RANDOM_INPUT(message, 64);
    hydro_sign_keypair key_pair;
    hydro_sign_keygen(&key_pair);
    uint8_t sig[hydro_sign_BYTES];
    hydro_sign_create(sig, message, 64, "Benchmark", key_pair.sk);

    TIMING_START {
        if (hydro_sign_verify(sig, message, 64, "Benchmark", key_pair.pk)) {
            printf("LibHydrogen verification failed\n");
        }
    }
    TIMING_END;
}

int main()
{
    hydro_init();
    print("Random           ",hydro_random() *MUL,"megabytes  per second");
    print("Auth'd encryption",authenticated()*MUL,"megabytes  per second");
    print("Hash             ",hash()         *MUL,"megabytes  per second");
    print("sign             ",sign()             ,"signatures per second");
    print("check            ",check()            ,"checks     per second");
    printf("\n");
    return 0;
}
