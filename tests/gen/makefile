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
CC     ?= gcc -std=c99
CFLAGS ?= -pedantic -Wall -Wextra

.PHONY: all clean

VEC     = chacha20 hchacha20 xchacha20 ietf_chacha20             \
          aead_ietf aead_8439                                    \
          poly1305 blake2b sha512 sha512_hmac sha512_hkdf argon2 \
          edDSA edDSA_pk ed_25519 ed_25519_pk ed_25519_check     \
          ed_25519ph                                             \
          x25519 x25519_pk elligator_inv elligator_dir
VEC2    = $(patsubst %, %.all.vec, $(VEC))
HEADERS = $(patsubst %, %.h.vec  , $(VEC))
VECTORS = ../vectors.h

all: $(VECTORS)

clean:
	rm -f *.out *.vec *.o
	rm -f $(VECTORS)

elligator_inv.vec: elligator-inverse.py elligator.py elligator_scalarmult.py
	./$< >$@
elligator_dir.vec: elligator-direct.py elligator.py
	./$< >$@
sha512_hkdf.vec: sha512_hkdf.py
	./$< >$@
%.vec: %.out
	./$< > $@

utils.o: utils.c utils.h
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

chacha20.all.vec      : chacha20.vec      vectors/chacha20
poly1305.all.vec      : poly1305.vec      vectors/poly1305
x25519.all.vec        : x25519.vec        vectors/x25519
x25519_pk.all.vec     : x25519_pk.vec
hchacha20.all.vec     : hchacha20.vec
xchacha20.all.vec     : xchacha20.vec
ietf_chacha20.all.vec : ietf_chacha20.vec
aead_ietf.all.vec     : aead_ietf.vec
aead_8439.all.vec     : aead_8439.vec
blake2b.all.vec       : blake2b.vec       vectors/blake2b
sha512.all.vec        : sha512.vec
sha512_hmac.all.vec   : sha512_hmac.vec   vectors/sha512_hmac
sha512_hkdf.all.vec   : sha512_hkdf.vec
argon2.all.vec        : argon2.vec        vectors/argon2
edDSA.all.vec         : edDSA.vec
edDSA_pk.all.vec      : edDSA_pk.vec
ed_25519.all.vec      : ed_25519.vec
ed_25519_pk.all.vec   : ed_25519_pk.vec
ed_25519_check.all.vec:                   vectors/ed_25519_check
ed_25519ph.all.vec    :                   vectors/ed_25519ph
elligator_dir.all.vec : elligator_dir.vec vectors/elligator_dir
elligator_inv.all.vec : elligator_inv.vec vectors/elligator_inv
$(VEC2):
	mkdir -p $(@D)
	cat $^ > $@

%.h.vec: %.all.vec vector_to_header.out
	./vector_to_header.out  $(patsubst %.all.vec,%,$<) < $< > $@

prelude.h.vec:
	@echo "creating prelude.h.vec"
	@echo "// Generated with hard coded official vectors, and"     >  $@
	@echo "// random vectors with libsodium and ed25519-donna."    >> $@
	@echo "// Download Monocypher's git repository to regenerate." >> $@
	@echo "#include <inttypes.h>"                                  >> $@
	@echo "#include <stddef.h>"                                    >> $@
	@echo ""                                                       >> $@

$(VECTORS): prelude.h.vec $(HEADERS)
	cat $^ > $@
