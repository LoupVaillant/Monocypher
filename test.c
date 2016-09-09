#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>
#include "chacha20.h"

static void*
alloc(size_t size)
{
    void *buffer = malloc(size);
    if (buffer == NULL) {
        fprintf(stderr, "Allocation failed\n");
        exit(1);
    }
    return buffer;
}

static unsigned
uint_of_char(unsigned char c)
{
    if (c >= '0' && c <= '9') { return c - '0';      }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    fprintf(stderr, "Not a hexadecimal char\n");
    exit(1);
}

static uint8_t*
ascii_to_raw(const char *ascii)
{
    const size_t len = strlen(ascii);
    if (len % 2 != 0) {
        fprintf(stderr, "Hexa string has an odd length\n");
        exit(1);
    }
    const size_t size = len / 2;
    uint8_t     *raw  = alloc(size);
    for (unsigned i = 0; i < size; i++) {
        unsigned msb = uint_of_char(ascii[2*i + 0]);
        unsigned lsb = uint_of_char(ascii[2*i + 1]);
        raw[i]       = lsb | (msb << 4);
    }
    return raw;
}

static const char*
test_chacha20(const char *key, const char *nonce, const char *stream)
{
    uint8_t *k    = ascii_to_raw(key);
    uint8_t *n    = ascii_to_raw(nonce);
    uint8_t *s    = ascii_to_raw(stream);
    size_t   size = strlen(stream) / 2;
    uint8_t *out  = alloc(size);
    memset(out, 0, size);
    crypto_chacha_ctx ctx;

    crypto_init_chacha20(&ctx, k, n);
    crypto_encrypt_chacha20(&ctx, out, out, size);
    int match = memcmp(out, s, size) == 0;

    free(out);
    free(s);
    free(n);
    free(k);
    return match ? "OK" : "FAIL! ABORT! REVIEW!";
}

static void
chacha20(void)
{
    static const char *k0 =
        "0000000000000000000000000000000000000000000000000000000000000000";
    static const char *k1 =
        "0000000000000000000000000000000000000000000000000000000000000001";
    static const char *kr =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    static const char *n0 = "0000000000000000";
    static const char *n1 = "0000000000000001";
    static const char *n2 = "0100000000000000";
    static const char *nr = "0001020304050607";

    static const char *s00 =
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc"
        "8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11c"
        "c387b669b2ee6586";
    static const char *s10 =
        "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952"
        "ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea81"
        "7e9ad275ae546963";
    static const char *s01 =
        "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df1"
        "37821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e"
        "445f41e3";
    static const char *s02 =
        "ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd1"
        "38e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d"
        "6bbdb0041b2f586b";
    static const char *srr =
        "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56"
        "f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f1"
        "5916155c2be8241a38008b9a26bc35941e2444177c8ade6689de9526"
        "4986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e"
        "09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a4750"
        "32b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c5"
        "07b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f7"
        "6dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2"
        "ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab7"
        "8fab78c9";

    printf("Chacha20, stream 0 0: %s\n", test_chacha20(k0, n0, s00));
    printf("Chacha20, stream 1 0: %s\n", test_chacha20(k1, n0, s10));
    printf("Chacha20, stream 0 1: %s\n", test_chacha20(k0, n1, s01));
    printf("Chacha20, stream 0 2: %s\n", test_chacha20(k0, n2, s02));
    printf("Chacha20, stream r r: %s\n", test_chacha20(kr, nr, srr));
}

int main(void)
{
    chacha20();
    return 0;
}
