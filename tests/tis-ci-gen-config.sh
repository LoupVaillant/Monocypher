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
# Copyright (c) 2020, Loup Vaillant
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
# Written in 2020 by Loup Vaillant
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

DIR=$(dirname "$0")
TIS_CONFIG=$DIR/../tis.config

echo "// auto generated with $0" > $TIS_CONFIG
echo "[" >> $TIS_CONFIG

for entry_point in      \
    "p_wipe"            \
    "v_chacha20"        \
    "v_ietf_chacha20"   \
    "v_hchacha20"       \
    "v_xchacha20"       \
    "v_poly1305"        \
    "v_aead_ietf"       \
    "v_blake2b"         \
    "v_sha512"          \
    "v_sha512_hmac"     \
    "v_sha512_hkdf"     \
    "v_argon2"          \
    "v_x25519"          \
    "v_edDSA"           \
    "v_edDSA_pk"        \
    "v_ed_25519"        \
    "v_ed_25519_check"  \
    "v_elligator_dir"   \
    "v_elligator_inv"   \
    "p_eddsa_x25519"    \
    "p_dirty"           \
    "p_x25519_inverse"  \
    "p_verify16"        \
    "p_verify32"        \
    "p_verify64"
do
    for platform in   \
        "x86_16"      \
        "sparc_32"    \
        "x86_32"      \
        "rv64ifdq"    \
        "mips_64"
    do
        echo '{ "name"          :' "\"$entry_point - $platform\"" >> $TIS_CONFIG
        echo ', "files"         :'                                >> $TIS_CONFIG
        echo '  [ "src/monocypher.c"'                             >> $TIS_CONFIG
        echo '  , "src/optional/monocypher-ed25519.c"'            >> $TIS_CONFIG
        echo '  , "tests/utils.c"'                                >> $TIS_CONFIG
        echo '  , "tests/tis-ci.c"'                               >> $TIS_CONFIG
        echo '  ]'                                                >> $TIS_CONFIG
        echo ', "cpp-extra-args":
        "-Isrc -Isrc/optional -Itests -Dvolatile=
         -DCLOCK_PROCESS_CPUTIME_ID=3 -DCLOCK_THREAD_CPUTIME_ID=4"' \
                                                                  >> $TIS_CONFIG
        echo ', "machdep"       :' "\"$platform\""                >> $TIS_CONFIG
        echo ', "no-results"    : true'                           >> $TIS_CONFIG
        echo ', "main"          :' "\"$entry_point\""             >> $TIS_CONFIG
        echo '},'                                                 >> $TIS_CONFIG
    done
done
sed -i '$ d' $TIS_CONFIG

echo "}" >> $TIS_CONFIG
echo "]" >> $TIS_CONFIG
