CC=gcc -std=gnu99 # speed tests don't work with -std=cxx, they need the POSIX extensions
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native
DESTDIR=
PREFIX=usr/local
PKGCONFIG=$(DESTDIR)/$(PREFIX)/lib/pkgconfig
MAN_DIR=$(DESTDIR)/$(PREFIX)/share/man/man3
SONAME=libmonocypher.so.3

VERSION=__git__

ifdef USE_ED25519
LINK_ED25519=lib/monocypher-ed25519.o
INSTALL_ED25519=cp src/optional/monocypher-ed25519.h $(DESTDIR)/$(PREFIX)/include
endif

.PHONY: all library static-library dynamic-library                     \
        install install-doc pkg-config-libhydrogen                     \
        check test                                                     \
        speed speed-sodium speed-tweetnacl speed-hydrogen speed-c25519 \
        clean uninstall                                                \
        dist

all    : library
install: library src/monocypher.h install-doc
	mkdir -p $(DESTDIR)/$(PREFIX)/include
	mkdir -p $(DESTDIR)/$(PREFIX)/lib
	mkdir -p $(PKGCONFIG)
	cp -P lib/libmonocypher.a lib/libmonocypher.so* $(DESTDIR)/$(PREFIX)/lib
	cp src/monocypher.h $(DESTDIR)/$(PREFIX)/include
	$(INSTALL_ED25519)
	@echo "Creating $(PKGCONFIG)/monocypher.pc"
	@echo "prefix=/$(PREFIX)"                > $(PKGCONFIG)/monocypher.pc
	@echo 'exec_prefix=$${prefix}'          >> $(PKGCONFIG)/monocypher.pc
	@echo 'libdir=$${exec_prefix}/lib'      >> $(PKGCONFIG)/monocypher.pc
	@echo 'includedir=$${prefix}/include'   >> $(PKGCONFIG)/monocypher.pc
	@echo ''                                >> $(PKGCONFIG)/monocypher.pc
	@echo 'Name: monocypher'                >> $(PKGCONFIG)/monocypher.pc
	@echo 'Version: ' $(VERSION)            >> $(PKGCONFIG)/monocypher.pc
	@echo 'Description: Easy to use, easy to deploy crypto library' \
                                                >> $(PKGCONFIG)/monocypher.pc
	@echo ''                                >> $(PKGCONFIG)/monocypher.pc
	@echo 'Libs: -L$${libdir} -lmonocypher' >> $(PKGCONFIG)/monocypher.pc
	@echo 'Cflags: -I$${includedir}'        >> $(PKGCONFIG)/monocypher.pc

install-doc:
	mkdir -p $(MAN_DIR)
	cp -PR doc/man/man3/*.3monocypher $(MAN_DIR)
ifdef USE_ED25519
	cp -PR doc/man/man3/optional/*.3monocypher $(MAN_DIR)
endif

pkg-config-libhydrogen:
	mkdir -p $(PKGCONFIG)
	@echo "Creating $(PKGCONFIG)/libhydrogen.pc"
	@echo "prefix=/$(PREFIX)"               > $(PKGCONFIG)/libhydrogen.pc
	@echo 'exec_prefix=$${prefix}'         >> $(PKGCONFIG)/libhydrogen.pc
	@echo 'libdir=$${exec_prefix}/lib'     >> $(PKGCONFIG)/libhydrogen.pc
	@echo 'includedir=$${prefix}/include'  >> $(PKGCONFIG)/libhydrogen.pc
	@echo ''                               >> $(PKGCONFIG)/libhydrogen.pc
	@echo 'Name: libhydrogen'              >> $(PKGCONFIG)/libhydrogen.pc
	@echo 'Version: git-HEAD'              >> $(PKGCONFIG)/libhydrogen.pc
	@echo 'Description: Small, easy-to-use,'      \
              'hard-to-misuse cryptographic library.' \
                                               >> $(PKGCONFIG)/libhydrogen.pc
	@echo ''                               >> $(PKGCONFIG)/libhydrogen.pc
	@echo 'Libs: -L$${libdir} -lhydrogen'  >> $(PKGCONFIG)/libhydrogen.pc
	@echo 'Cflags: -I$${includedir}'       >> $(PKGCONFIG)/libhydrogen.pc

library: static-library dynamic-library
static-library : lib/libmonocypher.a
dynamic-library: lib/libmonocypher.so lib/$(SONAME)

clean:
	rm -rf lib/
	rm -f  *.out

uninstall:
	rm -f $(DESTDIR)/$(PREFIX)/lib/libmonocypher.a
	rm -f $(DESTDIR)/$(PREFIX)/lib/libmonocypher.so*
	rm -f $(DESTDIR)/$(PREFIX)/include/monocypher.h
	rm -f $(PKGCONFIG)/monocypher.pc
	rm -f $(MAN_DIR)/*.3monocypher

check: test
test           : test.out
test-legacy    : test-legacy.out
speed          : speed.out
speed-sodium   : speed-sodium.out
speed-tweetnacl: speed-tweetnacl.out
speed-hydrogen : speed-hydrogen.out
speed-c25519   : speed-c25519.out
test test-legacy speed speed-sodium speed-tweetnacl speed-hydrogen speed-c25519:
	./$<

# Monocypher libraries
lib/libmonocypher.a: lib/monocypher.o $(LINK_ED25519)
	ar cr $@ $^
lib/libmonocypher.so: lib/$(SONAME)
	@mkdir -p $(@D)
	ln -sf `basename $<` $@
lib/$(SONAME): lib/monocypher.o $(LINK_ED25519)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$(SONAME) -o $@ $^
lib/monocypher-ed25519.o: src/optional/monocypher-ed25519.c \
                          src/optional/monocypher-ed25519.h
lib/chacha20.o  : src/deprecated/chacha20.c  src/deprecated/chacha20.h
lib/aead-incr.o : src/deprecated/aead-incr.c src/deprecated/aead-incr.h
lib/monocypher.o: src/monocypher.c src/monocypher.h
lib/monocypher.o lib/monocypher-ed25519.o lib/chacha20.o lib/aead-incr.o:
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -I src/optional -fPIC -c -o $@ $<

# Test & speed libraries
TEST_COMMON = tests/utils.h src/monocypher.h src/optional/monocypher-ed25519.h
TEST_LEGACY = $(TEST_COMMON) src/deprecated/chacha20.h src/deprecated/aead-incr.h
SPEED       = tests/speed
lib/utils.o          :tests/utils.c
lib/test.o           :tests/test.c               $(TEST_COMMON) tests/vectors.h
lib/test-legacy.o    :tests/test-legacy.c        $(TEST_LEGACY) tests/vectors.h
lib/speed.o          :$(SPEED)/speed.c           $(TEST_COMMON) $(SPEED)/speed.h
lib/speed-tweetnacl.o:$(SPEED)/speed-tweetnacl.c $(TEST_COMMON) $(SPEED)/speed.h
lib/utils.o lib/test.o lib/test-legacy.o lib/speed.o:
	@mkdir -p $(@D)
	$(CC) $(CFLAGS)                     \
            -I src -I src/optional -I tests \
            -fPIC -c -o $@ $<

lib/speed-tweetnacl.o:
	@mkdir -p $(@D)
	$(CC) $(CFLAGS)                                                  \
            -I src -I src/optional -I tests -I tests/externals/tweetnacl \
            -fPIC -c -o $@ $<

lib/speed-sodium.o:$(SPEED)/speed-sodium.c $(TEST_COMMON) $(SPEED)/speed.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS)                     \
            -I src -I src/optional -I tests \
            `pkg-config --cflags libsodium` \
            -fPIC -c -o $@ $<

lib/speed-hydrogen.o:$(SPEED)/speed-hydrogen.c $(TEST_COMMON) $(SPEED)/speed.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS)                       \
            -I src -I src/optional -I tests   \
            `pkg-config --cflags libhydrogen` \
            -fPIC -c -o $@ $<

C25519=         c25519 edsign ed25519 morph25519 fprime f25519 sha512
C25519_H=       $(patsubst %, tests/externals/c25519/%.h, $(C25519))
C25519_OBJECTS= $(patsubst %, lib/c25519/%.o,             $(C25519))
lib/c25519/c25519.o    : tests/externals/c25519/c25519.c     $(C25519_H)
lib/c25519/ed25519.o   : tests/externals/c25519/ed25519.c    $(C25519_H)
lib/c25519/edsign.o    : tests/externals/c25519/edsign.c     $(C25519_H)
lib/c25519/f25519.o    : tests/externals/c25519/f25519.c     $(C25519_H)
lib/c25519/fprime.o    : tests/externals/c25519/fprime.c     $(C25519_H)
lib/c25519/morph25519.o: tests/externals/c25519/morph25519.c $(C25519_H)
lib/c25519/sha512.o    : tests/externals/c25519/sha512.c     $(C25519_H)
$(C25519_OBJECTS):
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I tests/externals/c25519/ -c -o $@ $<

lib/speed-c25519.o:$(SPEED)/speed-c25519.c \
                   $(SPEED)/speed.h        \
                   $(TEST_COMMON)          \
                   $(C25519_HEADERS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I tests -I tests/externals/c25519 -c -o $@ $<


# test & speed executables
TEST_OBJ=  lib/utils.o lib/monocypher.o
test.out       : lib/test.o        $(TEST_OBJ) lib/monocypher-ed25519.o
test-legacy.out: lib/test-legacy.o $(TEST_OBJ) lib/chacha20.o lib/aead-incr.o
speed.out      : lib/speed.o       $(TEST_OBJ) lib/monocypher-ed25519.o
test.out test-legacy.out speed.out:
	$(CC) $(CFLAGS) -I src -I src/optional -o $@ $^
speed-sodium.out: lib/speed-sodium.o lib/utils.o
	$(CC) $(CFLAGS) -o $@ $^            \
            `pkg-config --cflags libsodium` \
            `pkg-config --libs   libsodium`
speed-hydrogen.out: lib/speed-hydrogen.o lib/utils.o
	$(CC) $(CFLAGS) -o $@ $^              \
            `pkg-config --cflags libhydrogen` \
            `pkg-config --libs   libhydrogen`
lib/tweetnacl.o: tests/externals/tweetnacl/tweetnacl.c \
                 tests/externals/tweetnacl/tweetnacl.h
	$(CC) $(CFLAGS) -c -o $@ $<
speed-tweetnacl.out: lib/speed-tweetnacl.o lib/tweetnacl.o lib/utils.o
speed-c25519.out   : lib/speed-c25519.o $(C25519_OBJECTS) lib/utils.o
speed-tweetnacl.out speed-c25519.out:
	$(CC) $(CFLAGS) -o $@ $^

tests/vectors.h:
	@echo ""
	@echo "======================================================"
	@echo " I cannot perform the tests without the test vectors."
	@echo " You must generate them.  This requires Libsodium."
	@echo " The following will generate the test vectors:"
	@echo ""
	@echo "     $ cd tests/gen"
	@echo "     $ make"
	@echo ""
	@echo " Alternatively, you can grab an official release."
	@echo " It will include the test vectors, so you won't"
	@echo " need libsodium."
	@echo "======================================================"
	@echo ""
	exit 1

dist: tests/vectors.h
	./dist.sh
