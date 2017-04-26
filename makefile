CC=gcc
CFLAGS=-O2 -Wall -Wextra -std=c11 -pedantic

.PHONY: all clean
# disable implicit rules
.SUFFIXES:

all: test sodium

clean:
	rm -f *.o *.gch test rename_*

# Test suite based on test vectors
test: test.c monocypher.o sha512.o
	$(CC) $(CFLAGS) -o $@ $^

# Test suite based on comparison with libsodium
C_SODIUM_FLAGS=$$(pkg-config --cflags libsodium)
LD_SODIUM_FLAGS=$$(pkg-config --libs libsodium)
sodium: sodium.c rename_monocypher.o rename_sha512.o
	$(CC) $(CFLAGS) -o $@ $^ $(C_SODIUM_FLAGS) $(LD_SODIUM_FLAGS)

# compile monocypher
# use -DED25519_SHA512 for ed25519 compatibility
rename_monocypher.o: rename_monocypher.c rename_monocypher.h rename_sha512.h
	$(CC) $(CFLAGS) -c $^ -DED25519_SHA512
monocypher.o: monocypher.c monocypher.h sha512.h
	$(CC) $(CFLAGS) -c $^ -DED25519_SHA512

# compile sha512.  Only used for ed15519 compatibility
sha512.o: sha512.c sha512.h
	$(CC) $(CFLAGS) -c $^
rename_sha512.o: rename_sha512.c rename_sha512.h
	$(CC) $(CFLAGS) -c $^

# change the "crypto_" prefix to the "rename_" prefix, so you can use
# monocypher with other crypto libraries without conflict.
rename_%.c: %.c
	sed 's/crypto_/rename_/g' <$^ >$@
	sed 's/monocypher.h/rename_monocypher.h/' -i $@
	sed 's/sha512.h/rename_sha512.h/'         -i $@
rename_%.h: %.h
	sed 's/crypto_/rename_/g' <$^ >$@
	sed 's/monocypher.h/rename_monocypher.h/' -i $@
	sed 's/sha512.h/rename_sha512.h/'         -i $@
