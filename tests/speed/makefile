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
# Copyright (c) 2023, Loup Vaillant
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
# Written in 2023 by Loup Vaillant
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

CC=gcc -std=gnu99
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native

.PHONY: speed speed-sodium speed-hydrogen speed-tweetnacl speed-c25519 \
        speed-donna \
        pkg-config-libhydrogen \
        clean

##################
## Main targets ##
##################
all: speed

speed          : speed.out
speed-sodium   : speed-sodium.out
speed-hydrogen : speed-hydrogen.out
speed-tweetnacl: speed-tweetnacl.out
speed-c25519   : speed-c25519.out
speed-donna    : speed-donna.out
speed speed-sodium speed-hydrogen speed-tweetnacl speed-c25519 speed-donna:
	./$<

clean:
	rm -f *.o *.out

####################
## Base libraries ##
####################

# Test utils
utils.o: ../utils.c ../utils.h
	$(CC) -c $(CFLAGS) -I .. $< -o $@

# Monocypher
monocypher.o: ../../src/monocypher.c ../../src/monocypher.h
	$(CC) -c $(CFLAGS) -I .. -I ../../src/ $< -o $@
monocypher-ed25519.o: ../../src/optional/monocypher-ed25519.c \
                      ../../src/optional/monocypher-ed25519.h \
                      ../../src/monocypher.h
	$(CC) -c $(CFLAGS) -I .. -I ../../src/ -I ../../src/optional $< -o $@

# TweetNaCl
tweetnacl.o: ../externals/tweetnacl/tweetnacl.c \
             ../externals/tweetnacl/tweetnacl.h
	$(CC) -c $(CFLAGS) -I .. $< -o $@

# C25519
C25519=c25519 edsign ed25519 morph25519 fprime f25519 sha512
C25519_HEADERS=$(patsubst %, ../externals/c25519/%.h, $(C25519))
C25519_OBJECTS=$(patsubst %, %.o,                     $(C25519))
c25519.o    : ../externals/c25519/c25519.c     $(C25519_HEADERS)
ed25519.o   : ../externals/c25519/ed25519.c    $(C25519_HEADERS)
edsign.o    : ../externals/c25519/edsign.c     $(C25519_HEADERS)
f25519.o    : ../externals/c25519/f25519.c     $(C25519_HEADERS)
fprime.o    : ../externals/c25519/fprime.c     $(C25519_HEADERS)
morph25519.o: ../externals/c25519/morph25519.c $(C25519_HEADERS)
sha512.o    : ../externals/c25519/sha512.c     $(C25519_HEADERS)
$(C25519_OBJECTS):
	$(CC) -c $(CFLAGS) -I ../externals/c25519/ -o $@ $<

# libhydrogen (only installs pkg-config)
DESTDIR=
PREFIX=usr/local
PKGCONFIGDIR=$(LIBDIR)/pkgconfig
pkg-config-libhydrogen:
	mkdir -p $(DESTDIR)/$(PKGCONFIGDIR)
	sed "s|PREFIX|$(PREFIX)|" libhydrogen.pc \
	    > $(DESTDIR)/$(PKGCONFIGDIR)/libhydrogen.pc

# Donna
DONNA_HEADERS=$(wildcard ../externals/ed25519-donna/*.h)
donna.o: ../externals/ed25519-donna/ed25519.c $(DONNA_HEADERS)
	$(CC) $(CFLAGS) -c $< -o$@  \
	    -DED25519_CUSTOMHASH    \
	    -DED25519_TEST          \
	    -DED25519_NO_INLINE_ASM \
	    -DED25519_FORCE_32BIT


######################
## Speed benchmarks ##
######################
speed.o           : speed.c           speed.h ../utils.h
	$(CC) -c $(CFLAGS) $< -o $@ -I .. -I ../../src/ -I ../../src/optional
speed-sodium.o    : speed-sodium.c    speed.h ../utils.h
	$(CC) -c $(CFLAGS) $< -o $@ -I ..
speed-hydrogen.o  : speed-hydrogen.c  speed.h ../utils.h
	$(CC) -c $(CFLAGS) $< -o $@ -I ..
speed-tweetnacl.o : speed-tweetnacl.c speed.h ../utils.h $(TWEET_HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@ -I .. -I ../externals/tweetnacl
speed-c25519.o    : speed-c25519.c    speed.h ../utils.h $(C25519_HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@ -I .. -I ../externals/c25519
speed-donna.o     : speed-donna.c     speed.h ../utils.h $(DONNA_HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@ -I .. -I ../externals/ed25519-donna

speed.out: speed.o utils.o monocypher.o monocypher-ed25519.o
	$(CC) $(CFLAGS) -o $@ $^
speed-sodium.out: speed-sodium.o utils.o
	$(CC) $(CFLAGS) -o $@ $^            \
	    `pkg-config --cflags libsodium` \
	    `pkg-config --libs   libsodium`
speed-donna.out: speed-donna.o donna.o utils.o
	$(CC) $(CFLAGS) -o $@ $^            \
	    `pkg-config --cflags libsodium` \
	    `pkg-config --libs   libsodium`
speed-hydrogen.out: speed-hydrogen.o utils.o
	$(CC) $(CFLAGS) -o $@ $^              \
	    `pkg-config --cflags libhydrogen` \
	    `pkg-config --libs   libhydrogen`
speed-tweetnacl.out: speed-tweetnacl.o tweetnacl.o utils.o
	$(CC) $(CFLAGS) -o $@ $^
speed-c25519.out   : speed-c25519.o $(C25519_OBJECTS) utils.o
	$(CC) $(CFLAGS) -o $@ $^
