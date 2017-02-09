#! /bin/bash

CC="gcc"
CFLAGS="-O2 -Wall -Wextra -std=c11"

$CC $CFLAGS -c chacha20.c
$CC $CFLAGS -c blake2b.c
$CC $CFLAGS -c poly1305.c
$CC $CFLAGS -c argon2i.c
$CC $CFLAGS -c ae.c
$CC $CFLAGS -c x25519.c
$CC $CFLAGS -c ed25519.c -DED25519_SHA512
$CC $CFLAGS -c lock.c
$CC $CFLAGS -c sha512.c
$CC $CFLAGS -c test.c

$CC $CFLAGS -o test test.o chacha20.o argon2i.o blake2b.o poly1305.o x25519.o ae.o lock.o sha512.o ed25519.o
