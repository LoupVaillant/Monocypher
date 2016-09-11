#! /bin/bash

CC="gcc"
CFLAGS="-O2 -Wall -Wextra -std=c11"

$CC $CFLAGS -c chacha20.c
$CC $CFLAGS -c blake2b.c
$CC $CFLAGS -c test.c

$CC $CFLAGS -o test test.o chacha20.o
