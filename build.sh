#! /bin/bash

CC="gcc"
CFLAGS="-O2 -Wall -Wextra -std=c11"

$CC $CFLAGS -c chacha20.c
$CC $CFLAGS -c blake2b.c
$CC $CFLAGS -c poly1305.c
$CC $CFLAGS -c argon2i.c
$CC $CFLAGS -c test.c

$CC $CFLAGS -o test test.o chacha20.o argon2i.o blake2b.o poly1305.o
$CC $CFLAGS -o speed_blake2b speed_blake2b.c blake2b.o
