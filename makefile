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

CFLAGS= -pedantic -Wall -Wextra -O3 -march=native
DESTDIR=
PREFIX=usr/local
PKGCONFIG=$(DESTDIR)/$(PREFIX)/lib/pkgconfig
MAN_DIR=$(DESTDIR)/$(PREFIX)/share/man/man3

.PHONY: all install-doc library static-library dynamic-library clean install test speed

all    : library
install: library src/monocypher.h install-doc
	mkdir -p $(DESTDIR)/$(PREFIX)/lib
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
	cp -r doc/man/man3/* $(MAN_DIR)

library: static-library dynamic-library
static-library : lib/libmonocypher.a
dynamic-library: lib/libmonocypher.so

clean:
	rm -rf lib/
	rm -f  *.out

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
lib/%.o: src/%.c src/%.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -fPIC -c -o $@ $<

# Test & speed libraries
lib/utils.o: tests/utils.c tests/utils.h
lib/test.o : tests/test.c  tests/utils.h src/monocypher.h src/sha512.h tests/vectors.h
lib/speed.o: tests/speed.c tests/utils.h src/monocypher.h src/sha512.h
lib/utils.o lib/test.o lib/speed.o:
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -fPIC -c -o $@ $<

# test & speed executables
test.out : lib/test.o  lib/monocypher.o lib/sha512.o lib/utils.o
speed.out: lib/speed.o lib/monocypher.o lib/sha512.o lib/utils.o
test.out speed.out:
	$(CC) $(CFLAGS) -I src -o $@ $^

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
