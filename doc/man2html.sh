#! /bin/sh

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
# Copyright (c) 2017, Loup Vaillant
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
# Written in 2017 and 2019 by Loup Vaillant and Fabio Scotoni
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

DIR=$(dirname "$0")

# clean before
rm -rf "$DIR/html"

convert() {
    MANS=$1
    HTML=$2
    for name in $(ls -1 "$MANS/" | sed 's/.3monocypher//')
    do
        test -f "$MANS/$name.3monocypher" || continue
        mandoc                            \
        -Oman=%N.html,style=style.css \
        -Thtml "$MANS/$name.3monocypher" \
        > "$DIR/html/$HTML/$name.html"
    done
    cp "$DIR/style.css" "$DIR/html/$HTML/"
}

mkdir -p "$DIR/html"
mkdir -p "$DIR/html/advanced"
mkdir -p "$DIR/html/optional"
mkdir -p "$DIR/html/deprecated"
convert "$DIR/man/man3"            "."
convert "$DIR/man/man3/advanced"   "advanced"
convert "$DIR/man/man3/optional"   "optional"
convert "$DIR/man/man3/deprecated" "deprecated"

substitute() {
    HTML=$1
    for file in $(ls -1 "$HTML/" | grep ".html$")
    do
        sed \
            -e 's|href="intro.html"|                         href="../intro.html"|                         '\
            -e 's|href="crypto_argon2i_general.html"|        href="../crypto_argon2i_general.html"|        '\
            -e 's|href="crypto_argon2i.html"|                href="../crypto_argon2i.html"|                '\
            -e 's|href="crypto_blake2b_final.html"|          href="../crypto_blake2b_final.html"|          '\
            -e 's|href="crypto_blake2b_general.html"|        href="../crypto_blake2b_general.html"|        '\
            -e 's|href="crypto_blake2b_general_init.html"|   href="../crypto_blake2b_general_init.html"|   '\
            -e 's|href="crypto_blake2b.html"|                href="../crypto_blake2b.html"|                '\
            -e 's|href="crypto_blake2b_init.html"|           href="../crypto_blake2b_init.html"|           '\
            -e 's|href="crypto_blake2b_update.html"|         href="../crypto_blake2b_update.html"|         '\
            -e 's|href="crypto_check.html"|                  href="../crypto_check.html"|                  '\
            -e 's|href="crypto_key_exchange.html"|           href="../crypto_key_exchange.html"|           '\
            -e 's|href="crypto_key_exchange_public_key.html"|href="../crypto_key_exchange_public_key.html"|'\
            -e 's|href="crypto_lock_aead.html"|              href="../crypto_lock_aead.html"|              '\
            -e 's|href="crypto_lock.html"|                   href="../crypto_lock.html"|                   '\
            -e 's|href="crypto_sign.html"|                   href="../crypto_sign.html"|                   '\
            -e 's|href="crypto_sign_public_key.html"|        href="../crypto_sign_public_key.html"|        '\
            -e 's|href="crypto_unlock_aead.html"|            href="../crypto_unlock_aead.html"|            '\
            -e 's|href="crypto_unlock.html"|                 href="../crypto_unlock.html"|                 '\
            -e 's|href="crypto_verify16.html"|               href="../crypto_verify16.html"|               '\
            -e 's|href="crypto_verify32.html"|               href="../crypto_verify32.html"|               '\
            -e 's|href="crypto_verify64.html"|               href="../crypto_verify64.html"|               '\
            -e 's|href="crypto_wipe.html"|                   href="../crypto_wipe.html"|                   '\
            -e 's|href="crypto_chacha20_ctr.html"|                      href="../advanced/crypto_chacha20_ctr.html"|                    '\
            -e 's|href="crypto_chacha20_H.html"|                        href="../advanced/crypto_chacha20_H.html"|                      '\
            -e 's|href="crypto_chacha20.html"|                          href="../advanced/crypto_chacha20.html"|                        '\
            -e 's|href="crypto_check_final.html"|                       href="../advanced/crypto_check_final.html"|                     '\
            -e 's|href="crypto_check_init_custom_hash.html"|            href="../advanced/crypto_check_init_custom_hash.html"|          '\
            -e 's|href="crypto_check_init.html"|                        href="../advanced/crypto_check_init.html"|                      '\
            -e 's|href="crypto_check_update.html"|                      href="../advanced/crypto_check_update.html"|                    '\
            -e 's|href="crypto_curve_to_hidden.html"|                   href="../advanced/crypto_curve_to_hidden.html"|                 '\
            -e 's|href="crypto_from_eddsa_private.html"|                href="../advanced/crypto_from_eddsa_private.html"|              '\
            -e 's|href="crypto_from_eddsa_public.html"|                 href="../advanced/crypto_from_eddsa_public.html"|               '\
            -e 's|href="crypto_hchacha20.html"|                         href="../advanced/crypto_hchacha20.html"|                       '\
            -e 's|href="crypto_hidden_key_pair.html"|                   href="../advanced/crypto_hidden_key_pair.html"|                 '\
            -e 's|href="crypto_hidden_to_curve.html"|                   href="../advanced/crypto_hidden_to_curve.html"|                 '\
            -e 's|href="crypto_ietf_chacha20_ctr.html"|                 href="../advanced/crypto_ietf_chacha20_ctr.html"|               '\
            -e 's|href="crypto_ietf_chacha20.html"|                     href="../advanced/crypto_ietf_chacha20.html"|                   '\
            -e 's|href="crypto_poly1305_final.html"|                    href="../advanced/crypto_poly1305_final.html"|                  '\
            -e 's|href="crypto_poly1305.html"|                          href="../advanced/crypto_poly1305.html"|                        '\
            -e 's|href="crypto_poly1305_init.html"|                     href="../advanced/crypto_poly1305_init.html"|                   '\
            -e 's|href="crypto_poly1305_update.html"|                   href="../advanced/crypto_poly1305_update.html"|                 '\
            -e 's|href="crypto_sign_final.html"|                        href="../advanced/crypto_sign_final.html"|                      '\
            -e 's|href="crypto_sign_init_first_pass_custom_hash.html"|  href="../advanced/crypto_sign_init_first_pass_custom_hash.html"|'\
            -e 's|href="crypto_sign_init_first_pass.html"|              href="../advanced/crypto_sign_init_first_pass.html"|            '\
            -e 's|href="crypto_sign_init_second_pass.html"|             href="../advanced/crypto_sign_init_second_pass.html"|           '\
            -e 's|href="crypto_sign_public_key_custom_hash.html"|       href="../advanced/crypto_sign_public_key_custom_hash.html"|     '\
            -e 's|href="crypto_sign_update.html"|                       href="../advanced/crypto_sign_update.html"|                     '\
            -e 's|href="crypto_x25519_dirty_fast.html"|                 href="../advanced/crypto_x25519_dirty_fast.html"|               '\
            -e 's|href="crypto_x25519_dirty_small.html"|                href="../advanced/crypto_x25519_dirty_small.html"|              '\
            -e 's|href="crypto_x25519.html"|                            href="../advanced/crypto_x25519.html"|                          '\
            -e 's|href="crypto_x25519_inverse.html"|                    href="../advanced/crypto_x25519_inverse.html"|                  '\
            -e 's|href="crypto_x25519_public_key.html"|                 href="../advanced/crypto_x25519_public_key.html"|               '\
            -e 's|href="crypto_xchacha20_ctr.html"|                     href="../advanced/crypto_xchacha20_ctr.html"|                   '\
            -e 's|href="crypto_xchacha20.html"|                         href="../advanced/crypto_xchacha20.html"|                       '\
            -i "$HTML/$file"
    done
}

substitute "$DIR/html"
substitute "$DIR/html/advanced"
substitute "$DIR/html/optional"
substitute "$DIR/html/deprecated"

for file in $(ls -1 "$DIR/html" | grep ".html$")
do
    sed 's|href="../|href="|' -i "$DIR/html/$file"
done
