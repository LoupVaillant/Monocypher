#include "speed.h"
#include "utils.h"
#include "c25519.h"
#include "edsign.h"

static u64 x25519(void)
{
    u8 in [32] = {9};
    u8 out[F25519_SIZE];
    FOR (i, 0, F25519_SIZE) {
        out[i] = c25519_base_x[i];
    }

    TIMING_START {
        c25519_prepare(in);
        c25519_smult(out, out, in);
    }
    TIMING_END;
}

void edsign_sec_to_pub(uint8_t *pub, const uint8_t *secret);

/* Produce a signature for a message. */
#define EDSIGN_SIGNATURE_SIZE  64

void edsign_sign(uint8_t *signature, const uint8_t *pub,
		 const uint8_t *secret,
		 const uint8_t *message, size_t len);

/* Verify a message signature. Returns non-zero if ok. */
uint8_t edsign_verify(const uint8_t *signature, const uint8_t *pub,
		      const uint8_t *message, size_t len);

static u64 edDSA_sign(void)
{
    RANDOM_INPUT(sk     , 32);
    RANDOM_INPUT(message, 64);
    u8 pk [32];
    u8 sig[64];
    edsign_sec_to_pub(pk, sk);

    TIMING_START {
        edsign_sign(sig, pk, sk, message, 64);
    }
    TIMING_END;
}

static u64 edDSA_check(void)
{
    RANDOM_INPUT(sk     , 32);
    RANDOM_INPUT(message, 64);
    u8 pk [32];
    u8 sig[64];
    edsign_sec_to_pub(pk, sk);
    edsign_sign(sig, pk, sk, message, 64);

    TIMING_START {
        if (!edsign_verify(sig, pk, message, 64)) {
            printf("c25519 verification failed\n");
        }
    }
    TIMING_END;
}

int main()
{
    print("x25519      ", x25519()     , "exchanges  per second");
    print("EdDSA(sign) ", edDSA_sign() , "signatures per second");
    print("EdDSA(check)", edDSA_check(), "checks     per second");
    printf("\n");
    return 0;
}
