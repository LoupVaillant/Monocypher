#! /usr/bin/env python3

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

import sys

def map_prepend(s, l):
    return [s + ": " + x for x in l]

def extract(lines, start='', sub=''):
    return [line.split(' ')[1].strip()
            for line in lines
            if (line.startswith(start) and line.__contains__(sub))]

def without(item, list):
    return [x for x in list if x != item]

def check_inside(lines, all_functions):
    errors = []

    no_history = []
    in_history = False
    for line in lines:
        if   line.startswith('.Sh HISTORY'): in_history = True
        elif line.startswith('.Sh')        : in_history = False
        if not in_history                  : no_history.append(line)

    nm = extract(no_history, '.Nm')
    fo = extract(no_history, '.Fo')
    fn = extract(no_history, '.Fn')
    fn = without('arc4random_buf', sorted(set(fn)))

    dupes_nm = sorted(set([x for x in nm if nm.count(x) > 1]))
    dupes_fo = sorted(set([x for x in fo if fo.count(x) > 1]))

    only_fo = [x for x in fo if nm           .count(x) == 0]
    only_nm = [x for x in nm if fo           .count(x) == 0]
    only_fn = [x for x in fn if fo           .count(x) == 0]
    no_src  = [x for x in fn if all_functions.count(x) == 0]

    if len(dupes_nm) > 0: errors.append('Duplicates in .Nm: ' + str(dupes_nm))
    if len(dupes_fo) > 0: errors.append('Duplicates in .Fo: ' + str(dupes_fo))
    if len(only_fo)  > 0: errors.append('Missing in .Nm: '    + str(only_fo))
    if len(only_nm)  > 0: errors.append('Only in .Nm: '       + str(only_nm))
    if len(only_fn)  > 0: errors.append('Only in .Fn: '       + str(only_fn))
    if len(no_src)   > 0: errors.append('Not in sources: '    + str(no_src))

    return errors

def check_xr(lines, all_nm):
    errors  = []
    xr      = sorted(set(extract(lines, '.Xr', '3monocypher')))
    dead_xr = [x for x in xr if all_nm.count(x) == 0]
    if len(dead_xr) > 0:
        errors.append('Dead .Xr: ' + str(dead_xr))
    return errors

# Every line from every doc file
all_lines = {}
for file_name in sys.argv[1:]:
    name = file_name.split('.')[0]
    with open(file_name) as file:
        all_lines[name] = file.readlines()

# All .Nm (to spot .Xr dead references)
all_nm = []
for lines in all_lines.values():
    all_nm += extract(lines, '.Nm')

# All functions from source files
all_functions = [x.strip()for x in sys.stdin.readlines()]

# Errors
errors = []
for name, lines in all_lines.items():
    if name != "intro": # skip internal checks for the intro page
        errors += map_prepend(name, check_inside(lines, all_functions))
    errors += map_prepend(name, check_xr(lines, all_nm))

# Undocumented functions
undocumented = [x for x in all_functions if all_nm.count(x) == 0]
if len(undocumented) > 0:
    errors.append('Undocumented functions: ' + str(undocumented))

# Print any error, then exit accordingly
if len(errors) != 0:
    for e in errors:
        print(e)
    exit(1)
