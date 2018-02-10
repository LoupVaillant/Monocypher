CC=gcc -std=c99

CFLAGS = -pedantic -Wall -Wextra
HASH   =
#HASH=-DED25519_SHA512

.PHONY: all clean

VEC     = chacha20.vec xchacha20.vec aead_ietf.vec poly1305.vec blake2b.vec \
          sha512.vec   argon2i.vec   edDSA.vec     x25519.vec
VEC2    = $(patsubst %.vec, %.all.vec, $(VEC)) key_exchange.all.vec
HEADERS = $(patsubst %.all.vec, %.h.vec, $(VEC2))
VECTORS = ../vectors.h

all: $(VECTORS)

clean:
	rm -f *.out *.vec *.o
	rm -f $(VECTORS)

%.vec: %.out
	./$< > $@

%.o: %.c ../utils.h ../ed25519-donna/ed25519.h
	$(CC) $(CFLAGS) -c $<     \
            -I ..                 \
            -I ../ed25519-donna   \
            -I ../../src          \
            -I ../../src/optional \
            $$(pkg-config --cflags libsodium)

%.out: %.o monocypher.o ed25519.o
	$(CC) $(CFLAGS) -o $@ $^ \
            $$(pkg-config --libs libsodium)

ed25519.o: ../ed25519-donna/ed25519.c  $(wildcard ../ed25519-donna/*.h)
	$(CC) $(CFLAGS) -c $<       \
            -I ../../src            \
            -I ../../src/optional   \
            $(HASH)                 \
            -DED25519_CUSTOMHASH    \
            -DED25519_TEST          \
            -DED25519_NO_INLINE_ASM \
            -DED25519_FORCE_32BIT

monocypher.o: ../../src/monocypher.c      ../../src/monocypher.h
m_sha512.o  : ../../src/optional/sha512.c ../../src/optional/sha512.h
monocypher.o m_sha512.o:
	$(CC) $(CFLAGS) -c $< -I ../../src -I ../../src/optional

vector_to_header.out: ../vector_to_header.c
	$(CC) $(CFLAGS) $< -o $@

chacha20.all.vec    : chacha20.vec  ../vectors/chacha20
poly1305.all.vec    : poly1305.vec  ../vectors/poly1305
x25519.all.vec      : x25519.vec    ../vectors/x25519
xchacha20.all.vec   : xchacha20.vec
aead_ietf.all.vec   : aead_ietf.vec
blake2b.all.vec     : blake2b.vec
sha512.all.vec      : sha512.vec
argon2i.all.vec     : argon2i.vec
edDSA.all.vec       : edDSA.vec
key_exchange.all.vec:               ../vectors/key_exchange
$(VEC2):
	mkdir -p $(@D)
	cat $^ > $@

%.h.vec: %.all.vec vector_to_header.out
	./vector_to_header.out  $(patsubst %.all.vec,%,$<) < $< > $@

 $(VECTORS): $(HEADERS)
	cat $^ > $@
