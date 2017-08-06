# compile with any of the following
CC=gcc -std=gnu99 # speed tests don't work with -std=cxx, they need the POSIX extensions
#CC=gcc -std=c99
#CC=gcc -std=c11
#CC=g++ -std=c++98
#CC=g++ -std=c++11
#CC=g++ -std=c++14
#CC=g++ -std=c++17
#CC=clang -std=c99
#CC=clang -std=c11
#CC=clang++ -std=c++98
#CC=clang++ -std=c++11
#CC=clang++ -std=c++14

# These may be used for tests (except speed)
#CC = clang -std=c99 -fsanitize=address
#CC = clang -std=c99 -fsanitize=memory
#CC = clang -std=c99 -fsanitize=undefined
#CC = clang -std=c99 -fprofile-instr-generate -fcoverage-mapping

CFLAGS= -I src -pedantic -Wall -Wextra -O3 -march=native

.PHONY: all clean directories
# disable implicit rules
.SUFFIXES:

all: self sodium donna

clean:
	rm -rf bin formal-analysis
	rm -f src/*.gch src/rename_*
	rm -f self sodium donna speed

TEST_DEPS=tests/self.c bin/monocypher.o bin/sha512.o
GEN_HEADERS=bin/argon2i.h      \
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

# self containted test suite (vectors and properties)
self: $(TEST_DEPS) $(GEN_HEADERS)
	$(CC) $(CFLAGS) -I bin -o $@ $(TEST_DEPS)

bin/vector: tests/vector_to_header.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^

bin/%.h: tests/vectors/% bin/vector
	@echo generate $@
	@bin/vector $$(basename $<) <$< >$@

# Test suite based on comparison with libsodium
C_SODIUM_FLAGS=$$(pkg-config --cflags libsodium)
LD_SODIUM_FLAGS=$$(pkg-config --libs libsodium)
sodium: tests/sodium.c bin/rename_monocypher.o bin/rename_sha512.o
	$(CC) $(CFLAGS) -o $@ $^ $(C_SODIUM_FLAGS) $(LD_SODIUM_FLAGS)

# Speed benchmark
speed: tests/speed.c bin/rename_monocypher.o bin/rename_sha512.o bin/tweetnacl.o bin/poly-donna.o
	$(CC) $(CFLAGS) -o $@ $^ $(C_SODIUM_FLAGS) $(LD_SODIUM_FLAGS)

bin/tweetnacl.o: tests/tweetnacl/tweetnacl.c tests/tweetnacl/tweetnacl.h
	$(CC) $(CFLAGS) -o $@ -c $<

bin/poly-donna.o: tests/poly1305-donna/poly1305-donna.c \
                  tests/poly1305-donna/poly1305-donna.h \
                  tests/poly1305-donna/poly1305-donna-32.h
	$(CC) $(CFLAGS) -o $@ -c $< -DPOLY1305_32BIT

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
	sed 's/crypto_/rename_/g'                 <$^  >$@1
	sed 's/monocypher.h/rename_monocypher.h/' <$@1 >$@2
	sed 's/sha512.h/rename_sha512.h/'         <$@2 >$@
rename_%.h: %.h
	sed 's/crypto_/rename_/g'                 <$^  >$@1
	sed 's/monocypher.h/rename_monocypher.h/' <$@1 >$@2
	sed 's/sha512.h/rename_sha512.h/'         <$@2 >$@

formal-analysis: $(GEN_HEADERS)                    \
         src/monocypher.c src/monocypher.h \
         src/sha512.c src/sha512.h         \
         tests/self.c
	@echo "copy sources to formal-analysis directory for analysis (frama-c or TIS)"
	@mkdir -p formal-analysis
	@cp $^ formal-analysis
	@echo "add #define ED25519_SHA512 on top of monocypher.c (for ed25519)"
	@echo "#define ED25519_SHA512" > formal-analysis/tmp
	@cat formal-analysis/tmp src/monocypher.c > formal-analysis/monocypher.c
