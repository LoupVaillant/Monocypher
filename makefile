CC=gcc -std=gnu99 # speed tests don't work with -std=cxx, they need the POSIX extensions
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native
DESTDIR=
PREFIX=usr/local
PKGCONFIG=$(DESTDIR)/$(PREFIX)/lib/pkgconfig
MAN_DIR=$(DESTDIR)/$(PREFIX)/share/man/man3

# override with x.y.z when making a proper tarball
TARBALL_VERSION=master
# avoids changing the current directory while we archive it
TARBALL_DIR=..

.PHONY: all library static-library dynamic-library \
        install install-doc                        \
        check test speed                           \
        clean uninstall                            \
        tarball

all    : library
install: library src/monocypher.h install-doc
	mkdir -p $(DESTDIR)/$(PREFIX)/include
	mkdir -p $(DESTDIR)/$(PREFIX)/lib
	mkdir -p $(PKGCONFIG)
	cp lib/libmonocypher.a lib/libmonocypher.so $(DESTDIR)/$(PREFIX)/lib
	cp src/monocypher.h $(DESTDIR)/$(PREFIX)/include
	@echo "Creating $(PKGCONFIG)/monocypher.pc"
	@echo "prefix=/$(PREFIX)"                > $(PKGCONFIG)/monocypher.pc
	@echo 'exec_prefix=$${prefix}'          >> $(PKGCONFIG)/monocypher.pc
	@echo 'libdir=$${exec_prefix}/lib'      >> $(PKGCONFIG)/monocypher.pc
	@echo 'includedir=$${prefix}/include'   >> $(PKGCONFIG)/monocypher.pc
	@echo ''                                >> $(PKGCONFIG)/monocypher.pc
	@echo 'Name: monocypher'                >> $(PKGCONFIG)/monocypher.pc
	@echo 'Version: 1.1.0'                  >> $(PKGCONFIG)/monocypher.pc
	@echo 'Description: Easy to use, easy to deploy crypto library' \
                                                >> $(PKGCONFIG)/monocypher.pc
	@echo ''                                >> $(PKGCONFIG)/monocypher.pc
	@echo 'Libs: -L$${libdir} -lmonocypher' >> $(PKGCONFIG)/monocypher.pc
	@echo 'Cflags: -I$${includedir}'        >> $(PKGCONFIG)/monocypher.pc

install-doc:
	mkdir -p $(MAN_DIR)
	cp -r doc/man/man3/*.3monocypher $(MAN_DIR)

library: static-library dynamic-library
static-library : lib/libmonocypher.a
dynamic-library: lib/libmonocypher.so

clean:
	rm -rf lib/
	rm -f  *.out

uninstall:
	rm $(DESTDIR)/$(PREFIX)/lib/libmonocypher.a
	rm $(DESTDIR)/$(PREFIX)/lib/libmonocypher.so
	rm $(DESTDIR)/$(PREFIX)/include/monocypher.h
	rm $(PKGCONFIG)/monocypher.pc
	rm $(MAN_DIR)/*.3monocypher

check: test
test: test.out
	./test.out

speed: speed.out
	./speed.out

# Monocypher libraries
lib/libmonocypher.a: lib/monocypher.o
	ar cr $@ $^
lib/libmonocypher.so: lib/monocypher.o
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ $^
lib/sha512.o    : src/optional/sha512.c src/optional/sha512.o
lib/monocypher.o: src/monocypher.c src/monocypher.h
lib/monocypher.o lib/sha512.o:
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -I src/optional -fPIC -c -o $@ $<

# Test & speed libraries
$TEST_COMMON=tests/utils.h src/monocypher.h src/optional/sha512.h
lib/utils.o: tests/utils.c tests/utils.h
lib/test.o : tests/test.c  $(TEST_COMMON) tests/vectors.h
lib/speed.o: tests/speed.c $(TEST_COMMON)
lib/utils.o lib/test.o lib/speed.o:
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -I src/optional -fPIC -c -o $@ $<

# test & speed executables
test.out : lib/test.o  lib/monocypher.o lib/sha512.o lib/utils.o
speed.out: lib/speed.o lib/monocypher.o lib/sha512.o lib/utils.o
test.out speed.out:
	$(CC) $(CFLAGS) -I src -I src/optional -o $@ $^

tests/vectors.h:
	@echo ""
	@echo "======================================================"
	@echo " I cannot perform the tests without the test vectors."
	@echo " You must generate them.  This requires Libsodium."
	@echo " The fowlowing will generate the test vectors:"
	@echo ""
	@echo "     $ cd tests/gen"
	@echo "     $ make"
	@echo ""
	@echo " Alternatively, you can grab an official release."
	@echo " It will include the test vectors, so you won't"
	@echo " need libsodium"
	@echo "======================================================"
	@echo ""
	return 1

tarball: tests/vectors.h
	doc/man2html.sh
	tar -czvf $(TARBALL_DIR)/monocypher-$(TARBALL_VERSION).tar.gz \
            -X tarball_ignore                                         \
            --transform='flags=r;s|^.|monocypher-$(TARBALL_VERSION)|' .
