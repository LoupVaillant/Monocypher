# This file is dual-licensed.  Choose whichever licence you want from
# the two licences listed below.
#
# The first licence is a regular 2-clause BSD licence.  The second licence
# is the CC-0 from Creative Commons. It is intended to release Monocypher
# to the public domain.  The BSD licence serves as a fallback option.
#
# SPDX-License-Identifier: BSD-2-Clause OR CC0-1.0
#
# ------------------------------------------------------------------------
#
# Copyright (c) 2017-2019, Loup Vaillant
# Copyright (c) 2017, 2019, Fabio Scotoni
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# ------------------------------------------------------------------------
#
# Written in 2017-2019 by Loup Vaillant and Fabio Scotoni
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>
CC=gcc -std=gnu99 # speed tests don't work with -std=cxx, they need the POSIX extensions
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native
DESTDIR=
PREFIX=usr/local
LIBDIR=$(PREFIX)/lib
INCLUDEDIR=$(PREFIX)/include
PKGCONFIGDIR=$(LIBDIR)/pkgconfig
MANDIR=$(PREFIX)/share/man/man3
SONAME=libmonocypher.so.3

VERSION=__git__

ifdef USE_ED25519
LINK_ED25519=lib/monocypher-ed25519.o
INSTALL_ED25519=cp src/optional/monocypher-ed25519.h $(DESTDIR)/$(INCLUDEDIR)
endif

.PHONY: all library static-library dynamic-library                     \
        install install-doc pkg-config-libhydrogen                     \
        check test ctgrind                                             \
        speed speed-sodium speed-tweetnacl speed-hydrogen speed-c25519 \
        speed-donna                                                    \
        clean uninstall                                                \
        dist

all    : library
install: library src/monocypher.h monocypher.pc install-doc
	mkdir -p $(DESTDIR)/$(INCLUDEDIR)
	mkdir -p $(DESTDIR)/$(LIBDIR)
	mkdir -p $(DESTDIR)/$(PKGCONFIGDIR)
	cp -P lib/libmonocypher.a lib/libmonocypher.so* $(DESTDIR)/$(LIBDIR)
	cp src/monocypher.h $(DESTDIR)/$(INCLUDEDIR)
	$(INSTALL_ED25519)
	sed "s|PREFIX|$(PREFIX)|"  monocypher.pc \
            > $(DESTDIR)/$(PKGCONFIGDIR)/monocypher.pc

install-doc:
	mkdir -p $(DESTDIR)/$(MANDIR)
	cp -PR doc/man/man3/*.3monocypher $(DESTDIR)/$(MANDIR)
ifdef USE_ED25519
	cp -PR doc/man/man3/optional/*.3monocypher $(DESTDIR)/$(MANDIR)
endif

pkg-config-libhydrogen:
	mkdir -p $(DESTDIR)/$(PKGCONFIGDIR)
	sed "s|PREFIX|$(PREFIX)|" tests/speed/libhydrogen.pc \
            > $(DESTDIR)/$(PKGCONFIGDIR)/libhydrogen.pc

library: static-library dynamic-library
static-library : lib/libmonocypher.a
dynamic-library: lib/libmonocypher.so lib/$(SONAME)

clean:
	rm -rf lib/
	rm -f  *.out

uninstall:
	rm -f $(DESTDIR)/$(LIBDIR)/libmonocypher.a
	rm -f $(DESTDIR)/$(LIBDIR)/libmonocypher.so*
	rm -f $(DESTDIR)/$(INCLUDEDIR)/monocypher.h
	rm -f $(DESTDIR)/$(INCLUDEDIR)/monocypher-ed25519.h
	rm -f $(DESTDIR)/$(PKGCONFIGDIR)/monocypher.pc
	rm -f $(DESTDIR)/$(MANDIR)/*.3monocypher

check: test
test           : test.out
test-legacy    : test-legacy.out
speed          : speed.out
speed-sodium   : speed-sodium.out
speed-tweetnacl: speed-tweetnacl.out
speed-hydrogen : speed-hydrogen.out
speed-c25519   : speed-c25519.out
speed-donna    : speed-donna.out
test test-legacy speed speed-sodium speed-tweetnacl speed-hydrogen speed-c25519 speed-donna:
	./$<

ctgrind: ctgrind.out
	valgrind ./ctgrind.out

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
lib/ctgrind.o        :tests/ctgrind.c            $(TEST_COMMON)
lib/speed.o          :$(SPEED)/speed.c           $(TEST_COMMON) $(SPEED)/speed.h
lib/speed-tweetnacl.o:$(SPEED)/speed-tweetnacl.c $(TEST_COMMON) $(SPEED)/speed.h
lib/utils.o lib/test.o lib/test-legacy.o lib/speed.o:
	@mkdir -p $(@D)
	$(CC) $(CFLAGS)                     \
            -I src -I src/optional -I tests \
            -fPIC -c -o $@ $<
lib/ctgrind.o: # suppress optimisations to maximise findings
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -O0                 \
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

lib/speed-donna.o:$(SPEED)/speed-donna.c $(TEST_COMMON) $(SPEED)/speed.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS)                                                      \
            -I src -I src/optional -I tests -I tests/externals/ed25519-donna \
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

lib/speed-ed25519.o: tests/externals/ed25519-donna/ed25519.c \
           $(wildcard tests/externals/ed25519-donna/*.h)
	$(CC) $(CFLAGS) -c $< -o$@            \
            -I src                            \
            -DUSE_MONOCYPHER                  \
            -DED25519_CUSTOMHASH              \
            -DED25519_TEST                    \
            -DED25519_NO_INLINE_ASM           \
            -DED25519_FORCE_32BIT

# test & speed executables
TEST_OBJ=  lib/utils.o lib/monocypher.o
test.out       : lib/test.o        $(TEST_OBJ) lib/monocypher-ed25519.o
test-legacy.out: lib/test-legacy.o $(TEST_OBJ) lib/chacha20.o lib/aead-incr.o
ctgrind.out    : lib/ctgrind.o     $(TEST_OBJ) lib/monocypher-ed25519.o
speed.out      : lib/speed.o       $(TEST_OBJ) lib/monocypher-ed25519.o
test.out test-legacy.out speed.out:
	$(CC) $(CFLAGS) -I src -I src/optional -o $@ $^
ctgrind.out:
	$(CC) $(CFLAGS) -O0 -I src -I src/optional -o $@ $^
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
speed-donna.out    : lib/speed-donna.o lib/speed-ed25519.o lib/utils.o lib/monocypher.o
speed-tweetnacl.out speed-c25519.out speed-donna.out:
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
