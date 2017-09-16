CC=gcc -std=c99
#CC = clang -std=c99 -fsanitize=address
#CC = clang -std=c99 -fsanitize=memory
#CC = clang -std=c99 -fsanitize=undefined
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native
HASH=
#HASH=-DED25519_SHA512

.PHONY: all clean

all: chacha20.vec \
     xchacha20.vec \
     poly1305.vec \
     blake2b.vec \
     sha512.vec \
     argon2i.vec \
     edDSA.vec \
     x25519.vec

clean:
	rm -f *.out
	rm -f *.vec
	rm -f *.o

%.vec: %.out
	./$< > $@

%.out: %.c donna.o ../../dist/tests/utils.c monocypher.o
	$(CC) $(CFLAGS) -o $@ $^              \
            -I ../../dist/tests               \
            -I ../ed25519-donna               \
            -I ../../dist/src                  \
            $$(pkg-config --cflags libsodium) \
            $$(pkg-config --libs   libsodium)

# Needed for EdDSA
donna.o: ../ed25519-donna/ed25519.c
	$(CC) $(CFLAGS) -o $@ -c $^ \
            -I ../../dist/src       \
            $(HASH)                 \
            -DED25519_CUSTOMHASH    \
            -DED25519_TEST          \
            -DED25519_NO_INLINE_ASM \
            -DED25519_FORCE_32BIT

# Needed for Blake2b in EdDSA
monocypher.o: ../../dist/src/monocypher.c
	$(CC) $(CFLAGS) -o $@ -c $^ \
            -I ../../dist/src

# Needed for Ed25519
sha512.o: ../../dist/src/sha512.c
	$(CC) $(CFLAGS) -o $@ -c $^ \
            -I ../../dist/src
