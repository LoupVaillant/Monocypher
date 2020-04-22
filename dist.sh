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
# Copyright (c) 2019, Loup Vaillant
# Copyright (c) 2019-2020, Fabio Scotoni
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
# Written in 2019-2020 by Loup Vaillant and Fabio Scotoni
#
# To the extent possible under law, the author(s) have dedicated all copyright
# and related neighboring rights to this software to the public domain
# worldwide.  This software is distributed without any warranty.
#
# You should have received a copy of the CC0 Public Domain Dedication along
# with this software.  If not, see
# <https://creativecommons.org/publicdomain/zero/1.0/>

set -e

VERSION=`git describe --tags`
FOLDER=monocypher-$VERSION
TARBALL=$FOLDER.tar

# Generate documentation for users who don't have mandoc
doc/man2html.sh

# Delete the destination folder just to make sure everything is clean.
# May be needed if we unpack the tarball in place for testing purposes,
# then run the release script again.
rm -rf $FOLDER

# copy everything except ignored files to the
rsync -ad --exclude-from=dist_ignore ./ $FOLDER

# Replace version markers by the actual version number (from tags)
find $FOLDER -type f -exec sed -i "s/__git__/$VERSION/g" \{\} \;

# Remove the dist target from the makefile (no recursive releases!),
# and the tests/vector.h target, which ships with the tarball.
sed -i '/tests\/vectors.h:/,$d' $FOLDER/makefile

# Remove contributor notes from the README
sed -e '/Contributor notes/,$d' \
    -e '1,/^---$/d' \
    -i $FOLDER/README.md
sed -e '1i\
Monocypher\
----------' \
    -i $FOLDER/README.md

# Make the actual tarball.  The options here were taken from:
# https://reproducible-builds.org/docs/archives/#full-example
# This requires GNU tar.
# The --mtime value was chosen arbitrarily, but the date is chosen such
# that it is after the release 3.1.0, the last one without reproducible
# tarballs.
tar --sort=name \
    --mtime=@1587513600 \
    --owner=0 --group=0 --numeric-owner \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    -cvf $TARBALL $FOLDER
# Compress separately so that we can set the -n option to avoid any kind
# of timestamp metadata
gzip -n $TARBALL

# Remove the temporary folder
rm -rf $FOLDER

# Run tests in the tarball, to make sure we didn't screw up anything
# important.  We're missing the TIS interpreter run, but that's a good
# quick check.
tar -xzf $TARBALL.gz
cd $FOLDER   # Extracting from the tarball, just to make sure
tests/test.sh
make clean
make speed
make speed-sodium
make speed-tweetnacl
make speed-hydrogen
make speed-c25519
make
