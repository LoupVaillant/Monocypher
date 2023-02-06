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

set -e

DIR=$(dirname "$0")

POLY=$DIR/poly1305.gen.py

echo "Check limb overflow: $POLY"

# Turn Poly1305 C code into Python code
echo "#! /bin/env python3"     >$POLY
echo "from overflow import *" >>$POLY
echo ""                       >>$POLY
cat $DIR/../../src/monocypher.c                                         |\
    sed -n "/PROOF Poly1305 /,/CQFD Poly1305 /p"                        |\
    sed '1d;$d'                                                         |\
    sed 's|	||'                                                         |\
    sed 's|//- ||'                                                      |\
    sed 's|^.*//-.*$||'                                                 |\
    sed 's|  *//.*||'                                                   |\
    sed 's|//|#|'                                                       |\
    sed 's|const ||'                                                    |\
    sed 's|;||'                                                         |\
    sed 's|ctx->|ctx_|'                                                 |\
    sed 's|\[|_|g'                                                      |\
    sed 's|\]||g'                                                       |\
    sed 's|(\([a-zA-Z0-9_]*\))\([a-zA-Z0-9_]*\)|\1(\2)|g'               |\
    sed 's|^\([a-zA-Z0-9_]*\) \([a-zA-Z0-9_]*\) = \(.*\)$|\2 = \1(\3)|' |\
    sed 's|\* \([0-9][0-9]*\)|\* cast(\1)|g'                            |\
    sed 's|\+ \([0-9][0-9]*\)|\+ cast(\1)|g'                            |\
    sed 's|\- \([0-9][0-9]*\)|\- cast(\1)|g'                            |\
    cat >>$POLY

# Run self-checking Python code
python3 $DIR/poly1305.gen.py

echo "No limb overflow detected"
