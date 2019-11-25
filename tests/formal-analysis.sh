#! /bin/sh

mkdir -p tests/formal-analysis
cp src/monocypher.c      \
   src/monocypher.h      \
   src/optional/sha512.h \
   src/optional/sha512.c \
   tests/utils.h         \
   tests/utils.c         \
   tests/test.c          \
   tests/vectors.h       \
   tests/formal-analysis
