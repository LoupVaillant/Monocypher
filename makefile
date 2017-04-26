CC=gcc
CFLAGS= -I src -O2 -Wall -Wextra -std=c11 -pedantic

.PHONY: all clean directories
# disable implicit rules
.SUFFIXES:

all: test sodium

clean:
	rm -rf bin
	rm -f src/*.gch src/rename_*
	rm -f test sodium

# Test suite based on test vectors
test: tests/test.c bin/monocypher.o bin/sha512.o
	$(CC) $(CFLAGS) -o $@ $^

# Test suite based on comparison with libsodium
C_SODIUM_FLAGS=$$(pkg-config --cflags libsodium)
LD_SODIUM_FLAGS=$$(pkg-config --libs libsodium)
sodium: tests/sodium.c bin/rename_monocypher.o bin/rename_sha512.o
	$(CC) $(CFLAGS) -o $@ $^ $(C_SODIUM_FLAGS) $(LD_SODIUM_FLAGS)

# compile monocypher
# use -DED25519_SHA512 for ed25519 compatibility
bin/rename_monocypher.o: src/rename_monocypher.c src/rename_monocypher.h src/rename_sha512.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $< -DED25519_SHA512
bin/monocypher.o: src/monocypher.c src/monocypher.h src/sha512.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $< -DED25519_SHA512

# compile sha512.  Only used for ed15519 compatibility
bin/sha512.o: src/sha512.c src/sha512.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $<
bin/rename_sha512.o: src/rename_sha512.c src/rename_sha512.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $<

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
