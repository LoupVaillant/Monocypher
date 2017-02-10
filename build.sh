#! /bin/bash

CC="gcc"
CFLAGS="-O2 -Wall -Wextra -std=c11"

$CC $CFLAGS -c monocypher.c -DED25519_SHA512
$CC $CFLAGS -c sha512.c
$CC $CFLAGS -c test.c
$CC $CFLAGS -o test test.o monocypher.o sha512.o
