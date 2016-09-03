#! /bin/bash

CC="gcc"
CFLAGS="-O2 -Wall -Wextra -std=c11"

$CC $CFLAGS -c chacha20.c
