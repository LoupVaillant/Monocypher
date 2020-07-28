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

echo "// auto generated with tests/gen-tis-config.sh" > $TIS_CONFIG
echo "[" >> $TIS_CONFIG

for entry_point in \
    "v_chacha20"                   \
    "v_ietf_chacha20"              \
    "v_hchacha20"                  \
    "v_xchacha20"                  \
    "v_poly1305"                   \
    "v_aead_ietf"                  \
    "v_blake2b"                    \
    "v_sha512"                     \
    "v_hmac_sha512"                \
    "v_argon2i"                    \
    "v_x25519"                     \
    "v_x25519_pk"                  \
    "v_key_exchange"               \
    "v_edDSA"                      \
    "v_edDSA_pk"                   \
    "v_ed_25519"                   \
    "v_ed_25519_pk"                \
    "v_ed_25519_check"             \
    "v_elligator_dir"              \
    "v_elligator_inv"              \
    "test_x25519"                  \
    "p_verify16"                   \
    "p_verify32"                   \
    "p_verify64"                   \
    "p_chacha20_ctr"               \
    "p_chacha20_stream"            \
    "p_chacha20_same_ptr"          \
    "p_hchacha20"                  \
    "p_poly1305"                   \
    "p_poly1305_overlap"           \
    "p_blake2b"                    \
    "p_blake2b_overlap"            \
    "p_sha512"                     \
    "p_sha512_overlap"             \
    "p_hmac_sha512"                \
    "p_hmac_sha512_overlap"        \
    "p_argon2i_easy"               \
    "p_argon2i_overlap"            \
    "p_x25519_overlap"             \
    "p_key_exchange_overlap"       \
    "p_eddsa_roundtrip"            \
    "p_eddsa_random"               \
    "p_eddsa_overlap"              \
    "p_eddsa_incremental"          \
    "p_aead"                       \
    "p_elligator_direct_msb"       \
    "p_elligator_direct_overlap"   \
    "p_elligator_inverse_overlap"  \
    "p_elligator_x25519"           \
    "p_elligator_key_pair"         \
    "p_elligator_key_pair_overlap" \
    "p_x25519_inverse"             \
    "p_x25519_inverse_overlap"     \
    "p_from_eddsa"                 \
    "p_from_ed25519"
do
    for platform in   \
        "sparc_64"    \
        "sparc_32"    \
        "x86_32"      \
        "x86_64"      \
        "x86_16"      \
        "x86_16_huge" \
        "x86_win32"   \
        "x86_win64"   \
        "armeb_eabi"  \
        "arm_eabi"    \
        "aarch64"     \
        "aarch64eb"   \
        "rv64ifdq"    \
        "rv32ifdq"    \
        "mips_o32"    \
        "mips_n32"    \
        "mips_64"     \
        "mipsel_64"   \
        "mipsel_n32"  \
        "apple_ppc_32"
    do
        echo '{ "name"           : "p1305 - sparc_64"'           >> $TIS_CONFIG
        echo ', "files"          :'                 \
             '["src/monocypher.c",'                 \
             '"src/optional/monocypher-ed25519.c",' \
             '"tests/test.c" ]'                                  >> $TIS_CONFIG
        echo ', "compilation_cmd": "-Isrc -Isrc/optional"'       >> $TIS_CONFIG
        echo ', "machdep"        :' "$platform"                  >> $TIS_CONFIG
#       echo ', "raw_options     : " { "-no-results" : "true" }' >> $TIS_CONFIG
        echo ', "main"           :' "$entry_point"               >> $TIS_CONFIG
        echo '},'                                                >> $TIS_CONFIG
    done
done
sed -i '$ d' $TIS_CONFIG

echo "}" >> $TIS_CONFIG
echo "]" >> $TIS_CONFIG
