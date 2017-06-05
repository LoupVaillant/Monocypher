CC=clang
CFLAGS= -I src -O2 -Wall -Wextra -std=c11 -pedantic -g

#-fno-stack-protector

.PHONY: all clean directories
# disable implicit rules
.SUFFIXES:

all: test sodium donna

clean:
	rm -rf bin
	rm -f src/*.gch src/rename_*
	rm -f test sodium donna

# Test suite based on test vectors
TEST_DEPS=tests/test.c bin/monocypher.o bin/sha512.o
test: $(TEST_DEPS)       \
      bin/argon2i.h      \
      bin/blake2b.h      \
      bin/blake2b_easy.h \
      bin/chacha20.h     \
      bin/ed25519_key.h  \
      bin/ed25519_sign.h \
      bin/h_chacha20.h   \
      bin/key_exchange.h \
      bin/poly1305.h     \
      bin/v_sha512.h     \
      bin/x25519.h       \
      bin/x_chacha20.h
	$(CC) $(CFLAGS) -I bin -o $@ $(TEST_DEPS)

bin/vector: tests/vector_to_header.c
	$(CC) $(CFLAGS) -o $@ $^

bin/%.h: tests/vectors/% bin/vector
	bin/vector $$(basename $<) <$< >$@

# Test suite based on comparison with libsodium
C_SODIUM_FLAGS=$$(pkg-config --cflags libsodium)
LD_SODIUM_FLAGS=$$(pkg-config --libs libsodium)
sodium: tests/sodium.c bin/rename_monocypher.o bin/rename_sha512.o
	$(CC) $(CFLAGS) -o $@ $^ $(C_SODIUM_FLAGS) $(LD_SODIUM_FLAGS)

# Test edDSA/blake2b by comparing with the donna implementation
# Note: we're using Blake2b, the default hash for monocypher edDSA
donna: tests/donna.c bin/classic_monocypher.o bin/donna.o
	$(CC) $(CFLAGS) -o $@ $^ -I tests/ed25519-donna
bin/classic_monocypher.o: src/monocypher.c src/monocypher.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $<
bin/donna.o: tests/ed25519-donna/ed25519.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $< -DED25519_CUSTOMHASH -DED25519_TEST -DED25519_NO_INLINE_ASM -DED25519_FORCE_32BIT

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
