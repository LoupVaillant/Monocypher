#! /bin/sh

mkdir -p formal-analysis
cp src/monocypher.c      \
   src/monocypher.h      \
   src/optional/sha512.h \
   src/optional/sha512.c \
   tests/utils.h         \
   tests/test.c          \
   tests/vectors.h       \
   tests/formal-analysis
