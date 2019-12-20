CC     = gcc -std=c99
CFLAGS = -pedantic -Wall -Wextra

.PHONY: all clean

VEC     = chacha20  hchacha20  xchacha20    ietf_chacha20 aead_ietf      \
          poly1305  blake2b    sha512       hmac_sha512   argon2i        \
          edDSA     edDSA_pk   ed_25519     ed_25519_pk   ed_25519_check \
          x25519    x25519_pk  key_exchange
VEC2    = $(patsubst %, %.all.vec, $(VEC))
HEADERS = $(patsubst %, %.h.vec  , $(VEC))
VECTORS = ../vectors.h

all: $(VECTORS)

clean:
	rm -f *.out *.vec *.o
	rm -f $(VECTORS)

%.vec: %.out
	./$< > $@

utils.o: ../utils.c ../utils.h
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.c ../utils.h ../externals/ed25519-donna/ed25519.h
	$(CC) $(CFLAGS) -c $<              \
            -I ..                          \
            -I ../externals/ed25519-donna  \
            -I ../../src                   \
            -I ../../src/optional          \
            $$(pkg-config --cflags libsodium)

%.out: %.o ed25519.o utils.o
	$(CC) $(CFLAGS) -o $@ $^ \
            $$(pkg-config --libs libsodium)

ed25519.o: ../externals/ed25519-donna/ed25519.c \
           $(wildcard ../externals/ed25519-donna/*.h)
	$(CC) $(CFLAGS) -c $<                 \
            -I ../../src                      \
            -I ../../src/optional             \
            $$(pkg-config --cflags libsodium) \
            -DED25519_CUSTOMHASH              \
            -DED25519_TEST                    \
            -DED25519_NO_INLINE_ASM           \
            -DED25519_FORCE_32BIT

vector_to_header.out: vector_to_header.c
	$(CC) $(CFLAGS) $< -o $@

chacha20.all.vec      : chacha20.vec    vectors/chacha20
poly1305.all.vec      : poly1305.vec    vectors/poly1305
x25519.all.vec        : x25519.vec      vectors/x25519
x25519_pk.all.vec     : x25519_pk.vec
hchacha20.all.vec     : hchacha20.vec
xchacha20.all.vec     : xchacha20.vec
ietf_chacha20.all.vec : ietf_chacha20.vec
aead_ietf.all.vec     : aead_ietf.vec
blake2b.all.vec       : blake2b.vec
sha512.all.vec        : sha512.vec
hmac_sha512.all.vec   : hmac_sha512.vec vectors/hmac_sha512
argon2i.all.vec       : argon2i.vec     vectors/argon2i
edDSA.all.vec         : edDSA.vec
edDSA_pk.all.vec      : edDSA_pk.vec
ed_25519.all.vec      : ed_25519.vec
ed_25519_pk.all.vec   : ed_25519_pk.vec
ed_25519_check.all.vec:                 vectors/ed_25519_check
key_exchange.all.vec  :                 vectors/key_exchange
$(VEC2):
	mkdir -p $(@D)
	cat $^ > $@

%.h.vec: %.all.vec vector_to_header.out
	./vector_to_header.out  $(patsubst %.all.vec,%,$<) < $< > $@

prelude.h.vec:
	@echo "creating prelude.h.vec"
	@echo "// Generated with hard coded official vectors, and"     >  $@
	@echo "// random vectors with Libsodium and ed25519-donna."    >> $@
	@echo "// Download Monocypher's git repository to regenerate." >> $@
	@echo "#include <inttypes.h>"                                  >> $@
	@echo "#include <stddef.h>"                                    >> $@
	@echo ""                                                       >> $@

$(VECTORS): prelude.h.vec $(HEADERS)
	cat $^ > $@
